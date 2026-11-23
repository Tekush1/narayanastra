//! eBPF rootkit detection (root only).
//!
//! eBPF rootkits (TripleCross, ebpfkit, boopkit, in-the-wild LinkPro) can hook the bpf()
//! syscall to hide their own programs from enumeration. We collect programs from four
//! independent views and flag anything one view sees and the bpf() syscall does not:
//!   (a) bpf(BPF_PROG_GET_NEXT_ID)             — the view the rootkit filters
//!   (b) prog_id in /proc/*/fdinfo               — programs held open by processes
//!   (c) bpf_prog_<tag>_<name> in /proc/kallsyms — JIT images in the kernel
//!   (d) pinned objects under /sys/fs/bpf        — via BPF_OBJ_GET
//! Plus helper-call analysis of the translated instructions and kernel-log warnings.

use crate::config::ScanConfig;
use crate::procfs;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

const MODULE: &str = "EBPF";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

const BPF_OBJ_GET: libc::c_long = 7;
const BPF_PROG_GET_NEXT_ID: libc::c_long = 11;
const BPF_PROG_GET_FD_BY_ID: libc::c_long = 13;
const BPF_OBJ_GET_INFO_BY_FD: libc::c_long = 15;

fn bpf(cmd: libc::c_long, attr: &mut [u8; 128]) -> i64 {
    unsafe { libc::syscall(libc::SYS_bpf, cmd, attr.as_mut_ptr(), attr.len() as u32) }
}

#[derive(Clone, Debug, Default)]
pub struct ProgInfo {
    pub id: u32,
    pub prog_type: u32,
    pub tag: String,
    pub name: String,
    pub uid: u32,
    pub helpers: Vec<String>,
}

pub fn prog_type_name(t: u32) -> &'static str {
    match t {
        1 => "socket_filter",
        2 => "kprobe",
        3 => "sched_cls",
        4 => "sched_act",
        5 => "tracepoint",
        6 => "xdp",
        7 => "perf_event",
        8 => "cgroup_skb",
        9 => "cgroup_sock",
        13 => "sock_ops",
        14 => "sk_skb",
        15 => "cgroup_device",
        17 => "raw_tracepoint",
        18 => "cgroup_sock_addr",
        22 => "flow_dissector",
        23 => "cgroup_sysctl",
        26 => "tracing",
        27 => "struct_ops",
        28 => "ext",
        29 => "lsm",
        30 => "sk_lookup",
        31 => "syscall",
        _ => "other",
    }
}

fn next_ids() -> Option<Vec<u32>> {
    let mut ids = Vec::new();
    let mut start = 0u32;
    loop {
        let mut attr = [0u8; 128];
        attr[0..4].copy_from_slice(&start.to_ne_bytes());
        if bpf(BPF_PROG_GET_NEXT_ID, &mut attr) != 0 {
            let errno = unsafe { *libc::__errno_location() };
            if errno == libc::ENOENT {
                break;
            }
            if ids.is_empty() {
                return None; // EPERM etc — no view at all
            }
            break;
        }
        let next = u32::from_ne_bytes([attr[4], attr[5], attr[6], attr[7]]);
        if next <= start {
            break;
        }
        ids.push(next);
        start = next;
        if ids.len() > 100_000 {
            break;
        }
    }
    Some(ids)
}

fn info_by_fd(fd: i32, helper_syms: &HashMap<u64, String>, call_base: Option<u64>) -> Option<ProgInfo> {
    let mut info = [0u8; 256];
    let mut attr = [0u8; 128];
    attr[0..4].copy_from_slice(&(fd as u32).to_ne_bytes());
    attr[4..8].copy_from_slice(&(info.len() as u32).to_ne_bytes());
    attr[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_ne_bytes());
    if bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr) != 0 {
        return None;
    }
    let u32_at = |b: &[u8], o: usize| u32::from_ne_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
    let prog_type = u32_at(&info, 0);
    let id = u32_at(&info, 4);
    let tag = util_hex(&info[8..16]);
    let xlated_len = u32_at(&info, 20) as usize;
    let uid = u32_at(&info, 48);
    let name_end = info[64..80].iter().position(|&b| b == 0).unwrap_or(16);
    let name = String::from_utf8_lossy(&info[64..64 + name_end]).into_owned();

    // second call: fetch translated instructions for helper analysis
    let mut helpers = Vec::new();
    if xlated_len > 0 && xlated_len < 4 * 1024 * 1024 {
        if let Some(base) = call_base {
            let mut insns = vec![0u8; xlated_len];
            let mut info2 = [0u8; 256];
            info2[20..24].copy_from_slice(&(xlated_len as u32).to_ne_bytes());
            info2[32..40].copy_from_slice(&(insns.as_mut_ptr() as u64).to_ne_bytes());
            let mut attr2 = [0u8; 128];
            attr2[0..4].copy_from_slice(&(fd as u32).to_ne_bytes());
            attr2[4..8].copy_from_slice(&(info2.len() as u32).to_ne_bytes());
            attr2[8..16].copy_from_slice(&(info2.as_mut_ptr() as u64).to_ne_bytes());
            if bpf(BPF_OBJ_GET_INFO_BY_FD, &mut attr2) == 0 {
                let mut seen = HashSet::new();
                for insn in insns.chunks_exact(8) {
                    // BPF_JMP|BPF_CALL with src_reg 0 = helper call; imm = offset from __bpf_call_base
                    if insn[0] == 0x85 && (insn[1] >> 4) == 0 {
                        let imm = i32::from_ne_bytes([insn[4], insn[5], insn[6], insn[7]]) as i64;
                        let addr = (base as i64).wrapping_add(imm) as u64;
                        if let Some(n) = helper_syms.get(&addr) {
                            if seen.insert(n.clone()) {
                                helpers.push(n.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    Some(ProgInfo { id, prog_type, tag, name, uid, helpers })
}

fn util_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn prog_by_id(id: u32, helper_syms: &HashMap<u64, String>, call_base: Option<u64>) -> Option<ProgInfo> {
    let mut attr = [0u8; 128];
    attr[0..4].copy_from_slice(&id.to_ne_bytes());
    let fd = bpf(BPF_PROG_GET_FD_BY_ID, &mut attr);
    if fd < 0 {
        return None;
    }
    let r = info_by_fd(fd as i32, helper_syms, call_base);
    unsafe { libc::close(fd as i32) };
    r
}

fn pinned_programs(helper_syms: &HashMap<u64, String>, call_base: Option<u64>) -> Vec<(String, ProgInfo)> {
    let mut out = Vec::new();
    let mut stack = vec![std::path::PathBuf::from("/sys/fs/bpf")];
    let mut visited = 0;
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for e in entries.flatten() {
            visited += 1;
            if visited > 20_000 {
                return out;
            }
            let p = e.path();
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => stack.push(p),
                Ok(m) if m.is_file() => {
                    let c = match std::ffi::CString::new(p.to_string_lossy().as_bytes()) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    let mut attr = [0u8; 128];
                    attr[0..8].copy_from_slice(&(c.as_ptr() as u64).to_ne_bytes());
                    attr[12..16].copy_from_slice(&(libc::O_RDONLY as u32).to_ne_bytes()); // BPF_F_RDONLY-ish
                    let fd = bpf(BPF_OBJ_GET, &mut attr);
                    // pins can be maps or links too — only programs carry prog info
                    let is_prog =
                        fd >= 0 && std::fs::read_link(format!("/proc/self/fd/{}", fd)).map(|t| t.to_string_lossy() == "anon_inode:bpf-prog").unwrap_or(false);
                    if fd >= 0 && !is_prog {
                        unsafe { libc::close(fd as i32) };
                    } else if fd >= 0 {
                        if let Some(info) = info_by_fd(fd as i32, helper_syms, call_base) {
                            if info.tag.len() == 16 && info.tag != "0000000000000000" {
                                out.push((p.to_string_lossy().into_owned(), info));
                            }
                        }
                        unsafe { libc::close(fd as i32) };
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Parse kallsyms for (a) __bpf_call_base, (b) bpf_* helper addresses, (c) JIT'd prog tags.
pub fn parse_kallsyms(ks: &str) -> (Option<u64>, HashMap<u64, String>, HashMap<String, String>) {
    let mut call_base = None;
    let mut helpers = HashMap::new();
    let mut jit_tags = HashMap::new(); // tag -> name
    for line in ks.lines() {
        let mut it = line.split_whitespace();
        let (addr, _ty, sym) = match (it.next(), it.next(), it.next()) {
            (Some(a), Some(t), Some(s)) => (a, t, s),
            _ => continue,
        };
        let a = u64::from_str_radix(addr, 16).unwrap_or(0);
        if sym == "__bpf_call_base" && a != 0 {
            call_base = Some(a);
        } else if let Some(rest) = sym.strip_prefix("bpf_prog_") {
            // bpf_prog_<16 hex tag>[_name]
            let tag: String = rest.chars().take(16).collect();
            if tag.len() == 16 && tag.chars().all(|c| c.is_ascii_hexdigit()) && line.ends_with("[bpf]") {
                let name = rest.get(17..).unwrap_or("").to_string();
                jit_tags.insert(tag, name);
            }
        } else if sym.starts_with("bpf_") && a != 0 {
            helpers.insert(a, sym.to_string());
        }
    }
    (call_base, helpers, jit_tags)
}

const RISKY_HELPERS: [(&str, &str); 6] = [
    ("bpf_probe_write_user", "writes into user-space memory of other processes (ebpfkit/TripleCross use it to tamper with sshd, sudo)"),
    ("bpf_override_return", "changes the return value of kernel functions (hide files, fake syscall results)"),
    ("bpf_send_signal", "kills/signals processes from kernel context"),
    ("bpf_send_signal_thread", "kills/signals threads from kernel context"),
    ("bpf_skb_store_bytes", "rewrites packets (fine in networking stacks, suspicious elsewhere)"),
    ("bpf_d_path", "resolves file paths (used to target specific files)"),
];

pub fn scan(cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    if !cfg.is_root {
        send(&tx, Finding::new(Severity::Info, MODULE, "eBPF", "eBPF inspection needs root — skipped").subject("noroot"));
        let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
        return;
    }
    progress(&tx, "Reading kallsyms for helper addresses and JIT'd program tags...");
    let ks = util::read_proc("/proc/kallsyms").unwrap_or_default();
    let (call_base, helper_syms, jit_tags) = parse_kallsyms(&ks);

    progress(&tx, "Enumerating programs via bpf(BPF_PROG_GET_NEXT_ID)...");
    let ids = match next_ids() {
        Some(i) => i,
        None => {
            send(&tx, Finding::new(Severity::Info, MODULE, "eBPF", "bpf() syscall unavailable (lockdown/seccomp/kernel config) — skipped").subject("nosys"));
            let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
            return;
        }
    };
    let progs: Vec<ProgInfo> = ids.iter().filter_map(|id| prog_by_id(*id, &helper_syms, call_base)).collect();
    let mut id_set: HashSet<u32> = ids.iter().copied().collect();
    let mut tag_set: HashSet<String> = progs.iter().map(|p| p.tag.clone()).collect();

    progress(&tx, "Cross-checking against /proc/*/fdinfo, kallsyms and /sys/fs/bpf...");
    // (b) fdinfo
    let mut holders: HashMap<u32, Vec<String>> = HashMap::new();
    for pid in util::proc_pids() {
        for (fd, target) in procfs::fds(pid) {
            if target != "anon_inode:bpf-prog" {
                continue;
            }
            if let Some(info) = util::read_proc(format!("/proc/{}/fdinfo/{}", pid, fd)) {
                if let Some(id) = info.lines().find_map(|l| l.strip_prefix("prog_id:").and_then(|v| v.trim().parse::<u32>().ok())) {
                    holders.entry(id).or_default().push(format!("{} (PID {})", procfs::comm(pid), pid));
                }
            }
        }
    }
    // programs loaded while we were looking are not hidden: re-enumerate once
    for id in next_ids().unwrap_or_default() {
        if id_set.insert(id) {
            if let Some(p) = prog_by_id(id, &helper_syms, call_base) {
                tag_set.insert(p.tag);
            }
        }
    }
    let mut hidden = 0;
    for (id, who) in &holders {
        if !id_set.contains(id) {
            hidden += 1;
            send(
                &tx,
                Finding::new(
                    Severity::Danger,
                    MODULE,
                    "Hidden eBPF",
                    &format!("eBPF program id {} is held by {} but hidden from bpf() enumeration", id, who.join(", ")),
                )
                .with_detail("The bpf() syscall itself is being filtered — eBPF/kernel rootkit")
                .subject(&format!("fd:{}", id)),
            );
        }
    }
    // (c) kallsyms JIT images
    for (tag, name) in &jit_tags {
        if !tag_set.contains(tag) {
            hidden += 1;
            send(
                &tx,
                Finding::new(
                    Severity::Danger,
                    MODULE,
                    "Hidden eBPF",
                    &format!(
                        "JIT'd eBPF program tag {} ({}) exists in kallsyms but not in bpf() enumeration",
                        tag,
                        if name.is_empty() { "unnamed" } else { name }
                    ),
                )
                .subject(&format!("ks:{}", tag)),
            );
        }
    }
    // (d) pins
    for (path, info) in pinned_programs(&helper_syms, call_base) {
        if !id_set.contains(&info.id) {
            hidden += 1;
            send(
                &tx,
                Finding::new(Severity::Danger, MODULE, "Hidden eBPF", &format!("Pinned program {} (id {}) is hidden from bpf() enumeration", path, info.id))
                    .subject(&format!("pin:{}", info.id)),
            );
        }
    }

    // helper analysis + inventory
    let mut by_type: HashMap<&str, usize> = HashMap::new();
    for p in &progs {
        *by_type.entry(prog_type_name(p.prog_type)).or_default() += 1;
        let tracing = matches!(p.prog_type, 2 | 5 | 7 | 17 | 26 | 29);
        for (h, why) in RISKY_HELPERS {
            if !p.helpers.iter().any(|x| x == h) {
                continue;
            }
            if h == "bpf_skb_store_bytes" && !tracing {
                continue;
            }
            let sev = if h == "bpf_probe_write_user" || h == "bpf_override_return" { Severity::Danger } else { Severity::Warning };
            send(
                &tx,
                Finding::new(sev, MODULE, "eBPF Hook", &format!("eBPF {} program '{}' (id {}) calls {}", prog_type_name(p.prog_type), p.name, p.id, h))
                    .with_detail(&format!(
                        "{}\nLoaded by uid {}; held by: {}",
                        why,
                        p.uid,
                        holders.get(&p.id).map(|v| v.join(", ")).unwrap_or_else(|| "nobody (pinned or attached)".into())
                    ))
                    .subject(&format!("helper:{}:{}", p.id, h)),
            );
        }
    }
    let inv: Vec<String> = by_type.iter().map(|(t, n)| format!("{}×{}", t, n)).collect();
    send(
        &tx,
        Finding::new(
            Severity::Info,
            MODULE,
            "eBPF",
            &format!("{} eBPF program(s) loaded: {}", progs.len(), if inv.is_empty() { "none".into() } else { inv.join(", ") }),
        )
        .with_detail(if call_base.is_none() { "Helper analysis unavailable (kallsyms addresses hidden — kptr_restrict)" } else { "" })
        .subject("inventory"),
    );
    if hidden == 0 {
        send(&tx, Finding::new(Severity::Safe, MODULE, "eBPF", "All eBPF programs visible in every view (bpf(), fdinfo, kallsyms, pins)").subject("xview"));
    }
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kallsyms_parsing() {
        let ks = "ffffffff81000000 T _stext\nffffffff811a0000 T __bpf_call_base\nffffffff811b2000 T bpf_probe_write_user\nffffffffc0123000 t bpf_prog_6deef7357e7b4530_sd_fw_egress\t[bpf]\nffffffffc0124000 t bpf_prog_aaaaaaaaaaaaaaaa\t[bpf]\n";
        let (base, helpers, tags) = parse_kallsyms(ks);
        assert_eq!(base, Some(0xffffffff811a0000));
        assert_eq!(helpers.get(&0xffffffff811b2000).map(|s| s.as_str()), Some("bpf_probe_write_user"));
        assert_eq!(tags.get("6deef7357e7b4530").map(|s| s.as_str()), Some("sd_fw_egress"));
        assert!(tags.contains_key("aaaaaaaaaaaaaaaa"));
    }
}
