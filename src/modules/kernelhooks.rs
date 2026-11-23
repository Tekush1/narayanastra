//! Kernel hook detection: ftrace/kprobe hooks, syscall-table integrity (via /proc/kcore),
//! kernel security posture and kernel-log evidence of rootkit module loads.

use crate::config::ScanConfig;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util;
use regex::Regex;
use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::FileExt;
use std::time::Instant;

const MODULE: &str = "KHOOKS";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

/// Functions rootkits hook to hide processes, files, sockets, modules or themselves.
pub const SENSITIVE: [&str; 30] = [
    "getdents",
    "getdents64",
    "filldir",
    "filldir64",
    "fillonedir",
    "iterate_dir",
    "kill",
    "tcp4_seq_show",
    "tcp6_seq_show",
    "udp4_seq_show",
    "udp6_seq_show",
    "packet_rcv",
    "tpacket_rcv",
    "vfs_read",
    "vfs_statx",
    "do_sys_open",
    "do_sys_openat2",
    "proc_pid_readdir",
    "proc_root_readdir",
    "bpf",
    "__sys_bpf",
    "bpf_prog_get_next_id",
    "find_task_by_vpid",
    "inet_ioctl",
    "audit_log_start",
    "load_module",
    "do_init_module",
    "sys_init_module",
    "kallsyms_lookup_name",
    "seq_read",
];

pub fn is_sensitive(func: &str) -> bool {
    let f = func.split('+').next().unwrap_or(func);
    let base = f
        .trim_start_matches("__x64_sys_")
        .trim_start_matches("__ia32_sys_")
        .trim_start_matches("__se_sys_")
        .trim_start_matches("__do_sys_")
        .trim_start_matches("ksys_");
    SENSITIVE.contains(&base) || SENSITIVE.contains(&f)
}

fn tracefs(path: &str) -> Option<String> {
    util::read_proc(format!("/sys/kernel/tracing/{}", path)).or_else(|| util::read_proc(format!("/sys/kernel/debug/tracing/{}", path)))
}

fn ftrace_hooks(tx: &Sender) {
    progress(tx, "Reading ftrace enabled_functions...");
    let content = match tracefs("enabled_functions") {
        Some(c) => c,
        None => {
            send(tx, Finding::new(Severity::Info, MODULE, "Ftrace Hook", "tracefs not mounted/readable — ftrace hook check skipped").subject("ftrace-na"));
            return;
        }
    };
    let owner_re = Regex::new(r"\[([A-Za-z0-9_\-]+)\]\s*$").expect("regex");
    let mut total = 0;
    let mut by_owner: BTreeMap<String, usize> = BTreeMap::new();
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        total += 1;
        let func = line.split_whitespace().next().unwrap_or("");
        let owner = owner_re.captures(line).map(|c| c[1].to_string()).unwrap_or_else(|| "kernel".into());
        *by_owner.entry(owner.clone()).or_default() += 1;
        if is_sensitive(func) {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Ftrace Hook", &format!("ftrace hook on sensitive kernel function {} (owner: {})", func, owner))
                    .with_detail(&format!(
                        "{}\nftrace-based rootkits (Reptile/KoviD/khook-style) redirect these to hide processes, files and sockets",
                        line.trim()
                    ))
                    .subject(&format!("ftrace:{}", func)),
            );
        }
    }
    if total > 0 {
        let owners: Vec<String> = by_owner.iter().map(|(o, n)| format!("{} ({})", o, n)).collect();
        send(
            tx,
            Finding::new(Severity::Info, MODULE, "Ftrace Hook", &format!("{} ftrace-attached function(s)", total))
                .with_detail(&format!("Owners: {}", owners.join(", ")))
                .subject("ftrace-total"),
        );
    }
}

fn kprobe_hooks(tx: &Sender) {
    progress(tx, "Reading kprobe lists...");
    let mut probes = Vec::new();
    if let Some(c) = util::read_proc("/sys/kernel/debug/kprobes/list") {
        for l in c.lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() >= 3 {
                probes.push((f[2].to_string(), l.trim().to_string()));
            }
        }
    }
    if let Some(c) = tracefs("kprobe_events") {
        for l in c.lines() {
            if let Some(sym) = l.split_whitespace().nth(1) {
                probes.push((sym.to_string(), format!("tracefs: {}", l.trim())));
            }
        }
    }
    let mut seen = HashSet::new();
    for (sym, line) in &probes {
        if is_sensitive(sym) && seen.insert(sym.clone()) {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Kernel Hook", &format!("kprobe on sensitive function {}", sym))
                    .with_detail(&format!("{}\nSecurity tools (tracee, bpftrace) also probe these — confirm the owner", line))
                    .subject(&format!("kprobe:{}", sym)),
            );
        }
    }
    if !probes.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "Kernel Hook", &format!("{} active kprobe(s)", probes.len())).subject("kprobe-total"));
    }
}

struct Kcore {
    f: std::fs::File,
    segs: Vec<(u64, u64, u64)>, // vaddr, offset, filesz
}

impl Kcore {
    fn open() -> Option<Kcore> {
        let f = std::fs::File::open("/proc/kcore").ok()?;
        let mut eh = [0u8; 64];
        f.read_exact_at(&mut eh, 0).ok()?;
        if &eh[..4] != b"\x7fELF" || eh[4] != 2 {
            return None;
        }
        let phoff = u64::from_le_bytes(eh[32..40].try_into().ok()?);
        let phentsize = u16::from_le_bytes([eh[54], eh[55]]) as u64;
        let phnum = u16::from_le_bytes([eh[56], eh[57]]) as u64;
        let mut segs = Vec::new();
        for i in 0..phnum.min(4096) {
            let mut ph = [0u8; 56];
            f.read_exact_at(&mut ph, phoff + i * phentsize).ok()?;
            if u32::from_le_bytes(ph[0..4].try_into().ok()?) != 1 {
                continue;
            }
            let off = u64::from_le_bytes(ph[8..16].try_into().ok()?);
            let vaddr = u64::from_le_bytes(ph[16..24].try_into().ok()?);
            let filesz = u64::from_le_bytes(ph[32..40].try_into().ok()?);
            segs.push((vaddr, off, filesz));
        }
        Some(Kcore { f, segs })
    }

    fn read(&self, vaddr: u64, len: usize) -> Option<Vec<u8>> {
        let (v, off, sz) = self.segs.iter().find(|(v, _, sz)| vaddr >= *v && vaddr + len as u64 <= v + sz)?;
        let _ = sz;
        let mut buf = vec![0u8; len];
        self.f.read_exact_at(&mut buf, off + (vaddr - v)).ok()?;
        Some(buf)
    }
}

fn syscall_table(tx: &Sender) {
    progress(tx, "Verifying syscall table entries via /proc/kcore...");
    let ks = match util::read_proc("/proc/kallsyms") {
        Some(k) => k,
        None => return,
    };
    let mut syms: Vec<(u64, String)> = Vec::new();
    let (mut stext, mut etext) = (0u64, 0u64);
    for line in ks.lines() {
        let mut it = line.split_whitespace();
        if let (Some(a), Some(_), Some(s)) = (it.next(), it.next(), it.next()) {
            let addr = u64::from_str_radix(a, 16).unwrap_or(0);
            if addr == 0 {
                continue;
            }
            match s {
                "_stext" => stext = addr,
                "_etext" => etext = addr,
                _ => {}
            }
            if !line.ends_with(']') {
                syms.push((addr, s.to_string()));
            }
        }
    }
    if stext == 0 || etext == 0 {
        send(
            tx,
            Finding::new(Severity::Info, MODULE, "Syscall Table", "Kernel addresses hidden (kptr_restrict) — syscall table check skipped").subject("sct-na"),
        );
        return;
    }
    syms.sort();
    let kcore = match Kcore::open() {
        Some(k) => k,
        None => {
            send(
                tx,
                Finding::new(Severity::Info, MODULE, "Syscall Table", "/proc/kcore unavailable (lockdown or container) — syscall table check skipped")
                    .subject("sct-na"),
            );
            return;
        }
    };
    let name_at = |addr: u64| syms.binary_search_by(|(a, _)| a.cmp(&addr)).ok().map(|i| syms[i].1.clone());
    let mut checked_any = false;
    for table in ["sys_call_table", "ia32_sys_call_table", "x32_sys_call_table"] {
        let addr = match syms.iter().find(|(_, s)| s == table) {
            Some((a, _)) => *a,
            None => continue,
        };
        let next = syms.iter().map(|(a, _)| *a).filter(|a| *a > addr).min().unwrap_or(addr + 8 * 512);
        let n = (((next - addr) / 8) as usize).clamp(1, 1024);
        let data = match kcore.read(addr, n * 8) {
            Some(d) => d,
            None => continue,
        };
        checked_any = true;
        let mut hooked = Vec::new();
        for (i, chunk) in data.chunks_exact(8).enumerate() {
            let p = u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8]));
            if p == 0 {
                continue;
            }
            if p < stext || p >= etext {
                hooked.push(format!("#{} -> {:#x} ({})", i, p, name_at(p).unwrap_or_else(|| "outside kernel text — module/heap".into())));
            }
        }
        if hooked.is_empty() {
            send(
                tx,
                Finding::new(Severity::Safe, MODULE, "Syscall Table", &format!("{}: all {} entries point into kernel text", table, n))
                    .subject(&format!("sct:{}", table)),
            );
        } else {
            send(
                tx,
                Finding::new(
                    Severity::Danger,
                    MODULE,
                    "Syscall Table",
                    &format!("{}: {} entr(y/ies) point outside kernel text — syscall hooks", table, hooked.len()),
                )
                .with_detail(&hooked.iter().take(20).cloned().collect::<Vec<_>>().join("\n"))
                .subject(&format!("sct:{}", table)),
            );
        }
    }
    if !checked_any {
        send(tx, Finding::new(Severity::Info, MODULE, "Syscall Table", "sys_call_table not readable via kcore — skipped").subject("sct-na"));
    }
}

pub fn taint_reasons(val: u64) -> Vec<&'static str> {
    let flags: [(u64, &str); 19] = [
        (0, "proprietary module (P)"),
        (1, "module force-loaded (F)"),
        (2, "SMP unsafe (S)"),
        (3, "module force-unloaded (R)"),
        (4, "machine check (M)"),
        (5, "bad page (B)"),
        (6, "user-requested taint (U)"),
        (7, "kernel died/OOPS (D)"),
        (8, "ACPI table overridden (A)"),
        (9, "kernel warning (W)"),
        (10, "staging driver (C)"),
        (11, "firmware bug workaround (I)"),
        (12, "out-of-tree module (O)"),
        (13, "unsigned module (E)"),
        (14, "soft lockup (L)"),
        (15, "live patched (K)"),
        (16, "auxiliary taint (X)"),
        (17, "struct randomization plugin (T)"),
        (18, "in-kernel test (N)"),
    ];
    flags.iter().filter(|(b, _)| val & (1 << b) != 0).map(|(_, s)| *s).collect()
}

fn posture(tx: &Sender) {
    progress(tx, "Checking kernel security posture...");
    if let Some(v) = util::read_proc("/proc/sys/kernel/tainted").and_then(|s| s.trim().parse::<u64>().ok()) {
        if v != 0 {
            let sev = if v & ((1 << 1) | (1 << 3) | (1 << 13)) != 0 { Severity::Warning } else { Severity::Info };
            send(tx, Finding::new(sev, MODULE, "Kernel Taint", &format!("Kernel tainted ({}): {}", v, taint_reasons(v).join(", "))).subject("taint"));
        }
    }
    let rd = |p: &str| util::read_proc(p).map(|s| s.trim().to_string());
    if let Some(l) = rd("/sys/kernel/security/lockdown") {
        let active = l.split_whitespace().find(|w| w.starts_with('[')).unwrap_or("[none]").to_string();
        send(
            tx,
            Finding::new(if active == "[none]" { Severity::Info } else { Severity::Safe }, MODULE, "Kernel Posture", &format!("Kernel lockdown: {}", active))
                .subject("lockdown"),
        );
    }
    let checks: [(&str, &str, &str); 5] = [
        ("/sys/module/module/parameters/sig_enforce", "Y", "Module signature enforcement"),
        ("/proc/sys/kernel/modules_disabled", "1", "Module loading disabled"),
        ("/proc/sys/kernel/kptr_restrict", "1", "kptr_restrict"),
        ("/proc/sys/kernel/unprivileged_bpf_disabled", "1", "Unprivileged eBPF disabled"),
        ("/proc/sys/kernel/kexec_load_disabled", "1", "kexec disabled"),
    ];
    let mut lines = Vec::new();
    for (p, good, label) in checks {
        if let Some(v) = rd(p) {
            lines.push(format!("{}: {}{}", label, v, if v == good || (good == "1" && v == "2") { " ✓" } else { "" }));
        }
    }
    if !lines.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "Kernel Posture", "Kernel hardening settings").with_detail(&lines.join("\n")).subject("posture"));
    }
}

/// Read the kernel ring buffer (non-blocking) and return its messages.
fn read_kmsg() -> Vec<String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let mut out = Vec::new();
    let mut f = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open("/dev/kmsg") {
        Ok(f) => f,
        Err(_) => return out,
    };
    let mut buf = vec![0u8; 8192];
    for _ in 0..200_000 {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let rec = String::from_utf8_lossy(&buf[..n]);
                if let Some((_, msg)) = rec.split_once(';') {
                    out.push(msg.lines().next().unwrap_or("").to_string());
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue, // overwritten record
            Err(_) => break,
        }
    }
    out
}

pub fn kmsg_module_evidence(lines: &[String]) -> (Vec<String>, Vec<String>) {
    let re = Regex::new(r"^([A-Za-z0-9_\-]+): (loading out-of-tree module taints kernel|module verification failed|module license .* taints kernel)")
        .expect("regex");
    let mut mods = Vec::new();
    let mut bpf_writers = Vec::new();
    for l in lines {
        if let Some(c) = re.captures(l) {
            let m = c[1].to_string();
            if !mods.contains(&m) {
                mods.push(m);
            }
        }
        if l.contains("bpf_probe_write_user") {
            bpf_writers.push(l.clone());
        }
    }
    (mods, bpf_writers)
}

fn kernel_log_evidence(tx: &Sender) {
    progress(tx, "Searching the kernel log for module-load and eBPF evidence...");
    let lines = read_kmsg();
    if lines.is_empty() {
        return;
    }
    let loaded: HashSet<String> =
        util::read_proc("/proc/modules").map(|c| c.lines().filter_map(|l| l.split_whitespace().next().map(String::from)).collect()).unwrap_or_default();
    let (mods, bpf_writers) = kmsg_module_evidence(&lines);
    let rk = ["diamorphine", "reptile", "bdvl", "suterusu", "kovid", "singularity", "rootkit", "hide"];
    for m in &mods {
        let lower = m.to_lowercase();
        if rk.iter().any(|r| lower.contains(r)) {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Rootkit Signature", &format!("Kernel log shows rootkit-named module '{}' was loaded", m))
                    .subject(&format!("kmsg:{}", m)),
            );
        } else if !loaded.contains(m) {
            send(
                tx,
                Finding::new(
                    Severity::Warning,
                    MODULE,
                    "Hidden Module",
                    &format!("Kernel log: out-of-tree/unsigned module '{}' was loaded but is no longer listed", m),
                )
                .with_detail("Either it was unloaded, or it is hiding from /proc/modules — correlate with the ROOTKIT module results")
                .subject(&format!("kmsg:{}", m)),
            );
        }
    }
    let present: Vec<&String> = mods.iter().filter(|m| loaded.contains(*m)).collect();
    if !present.is_empty() {
        send(
            tx,
            Finding::new(
                Severity::Info,
                MODULE,
                "Kernel Modules",
                &format!("Out-of-tree/unsigned modules currently loaded: {}", present.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")),
            )
            .subject("kmsg-present"),
        );
    }
    for l in bpf_writers.iter().take(10) {
        send(
            tx,
            Finding::new(Severity::Danger, MODULE, "eBPF Hook", "Kernel warned that a process loaded a bpf_probe_write_user program")
                .with_detail(l)
                .subject(&format!("kmsg-bpf:{}", util::truncate(l, 60))),
        );
    }
}

pub fn scan(cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    posture(&tx);
    if cfg.is_root {
        ftrace_hooks(&tx);
        kprobe_hooks(&tx);
        syscall_table(&tx);
        kernel_log_evidence(&tx);
    } else {
        send(&tx, Finding::new(Severity::Info, MODULE, "Kernel Hook", "ftrace/kprobe/syscall-table checks need root — skipped").subject("noroot"));
    }
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_functions() {
        assert!(is_sensitive("__x64_sys_getdents64"));
        assert!(is_sensitive("tcp4_seq_show+0x0/0x50"));
        assert!(is_sensitive("filldir64"));
        assert!(!is_sensitive("schedule"));
    }

    #[test]
    fn taint_decode() {
        let r = taint_reasons(4096 | 8192);
        assert_eq!(r, vec!["out-of-tree module (O)", "unsigned module (E)"]);
    }

    #[test]
    fn kmsg_evidence() {
        let lines = vec![
            "diamorphine: loading out-of-tree module taints kernel.".to_string(),
            "diamorphine: module verification failed: signature and/or required key missing - tainting kernel".to_string(),
            "evil[1234] is installing a program with bpf_probe_write_user helper that may corrupt user memory!".to_string(),
            "usb 1-1: new high-speed USB device".to_string(),
        ];
        let (mods, bpf) = kmsg_module_evidence(&lines);
        assert_eq!(mods, vec!["diamorphine".to_string()]);
        assert_eq!(bpf.len(), 1);
    }
}
