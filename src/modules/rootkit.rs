//! Cross-view rootkit detection: compare what the kernel *does* (syscall probes) with
//! what it *reports* (/proc listings, module lists, kallsyms).

use crate::config::ScanConfig;
use crate::pkg::{self, Ownership};
use crate::procfs;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use std::collections::HashSet;
use std::fs;
use std::time::{Duration, Instant};

const MODULE: &str = "ROOTKIT";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

/// Does `pid` exist according to direct syscalls (not directory listings)?
fn pid_alive(pid: u32, thorough: bool) -> bool {
    let p = pid as libc::pid_t;
    unsafe {
        let r = libc::kill(p, 0);
        if r == 0 || *libc::__errno_location() == libc::EPERM {
            return true;
        }
        if thorough {
            if libc::getpgid(p) >= 0 || libc::getsid(p) >= 0 {
                return true;
            }
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(p, std::mem::size_of::<libc::cpu_set_t>(), &mut set) == 0 {
                return true;
            }
        }
    }
    std::path::Path::new(&format!("/proc/{}/status", pid)).exists()
}

fn listed_pids_and_tids() -> (HashSet<u32>, HashSet<u32>) {
    let pids: HashSet<u32> = util::proc_pids().into_iter().collect();
    let mut tids = HashSet::new();
    for pid in &pids {
        for t in util::list_dir_raw(&format!("/proc/{}/task", pid)).unwrap_or_default() {
            if let Ok(t) = t.parse::<u32>() {
                tids.insert(t);
            }
        }
    }
    (pids, tids)
}

/// Hidden process detection by PID brute force (unhide-style):
/// probe every PID with kill(0)/getpgid/getsid/sched_getaffinity and compare against the
/// raw getdents64 listing of /proc. A getdents-hooking rootkit (Diamorphine, Reptile...)
/// removes the PID from the listing but the process still answers syscalls.
fn hidden_pids(cfg: &ScanConfig, tx: &Sender) {
    let pid_max: u32 = util::read_proc("/proc/sys/kernel/pid_max").and_then(|s| s.trim().parse().ok()).unwrap_or(32768).min(4_194_304);
    let (listed, tids) = listed_pids_and_tids();
    let highest = listed.iter().copied().max().unwrap_or(1);
    // quick mode: up to 2x the highest visible PID (min 65536); --full: whole pid space
    let limit = if cfg.full { pid_max } else { (highest.saturating_mul(2)).max(65536).min(pid_max) };
    progress(tx, &format!("Brute-forcing PIDs 1..{} against /proc listing...", limit));

    let mut candidates: Vec<u32> = (1..=limit).filter(|p| !listed.contains(p) && !tids.contains(p)).filter(|&p| pid_alive(p, cfg.full)).collect();

    // re-check twice to rule out processes that started/exited mid-scan
    for _ in 0..2 {
        if candidates.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
        let (listed2, tids2) = listed_pids_and_tids();
        candidates.retain(|p| !listed2.contains(p) && !tids2.contains(p) && pid_alive(*p, true));
    }
    // a TID of a visible process is not a hidden process
    candidates.retain(|p| {
        let st = procfs::status_fields(*p);
        match st.get("Tgid").and_then(|t| t.parse::<u32>().ok()) {
            Some(tgid) if tgid != *p => !listed.contains(&tgid),
            _ => true,
        }
    });

    if candidates.is_empty() {
        send(
            tx,
            Finding::new(Severity::Safe, MODULE, "PID Check", &format!("No hidden processes ({} PIDs listed, {} probed)", listed.len(), limit))
                .subject("pid-check"),
        );
        return;
    }
    for pid in candidates {
        let info = procfs::read_proc_info(pid);
        let detail = match &info {
            Some(i) => format!("Name: {}\nExe: {}\nCmdline: {}\nPPid: {}  Uid: {}", i.name, i.exe, i.cmdline, i.ppid, i.uid),
            None => "Process answers syscalls but /proc/<pid> details are also hidden".to_string(),
        };
        let mut f =
            Finding::new(Severity::Danger, MODULE, "Hidden PIDs", &format!("PID {} is alive but hidden from the /proc listing — rootkit process hiding", pid))
                .with_detail(&detail)
                .subject(&format!("pid:{}", pid));
        if let Some(i) = info {
            if !i.exe.is_empty() {
                f = f.artifact(&format!("/proc/{}/exe", pid));
            }
        }
        send(tx, f);
    }
}

fn deleted_binaries(tx: &Sender) {
    progress(tx, "Checking for processes running deleted or memfd binaries...");
    let root = Root::live();
    for pid in util::proc_pids() {
        let (exe, deleted) = procfs::exe(pid);
        if exe.is_empty() {
            continue;
        }
        let cmd = procfs::read_cmdline(pid);
        if exe.starts_with("/memfd:") {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Memfd Exec", &format!("PID {} executes from an anonymous memfd: {}", pid, exe))
                    .with_detail(&format!("Fileless execution (memfd_create + fexecve)\nCmdline: {}", cmd))
                    .subject(&format!("pid:{}", pid))
                    .artifact(&format!("/proc/{}/exe", pid)),
            );
            continue;
        }
        if !deleted {
            continue;
        }
        // Binary replaced by a package upgrade: path exists again and is package-owned.
        let replaced = fs::metadata(&exe).is_ok() && pkg::owner(&root, &exe) == Ownership::Owned;
        if replaced {
            send(
                tx,
                Finding::new(Severity::Info, MODULE, "Deleted Binary", &format!("PID {} runs an old copy of {} (upgraded since start)", pid, exe))
                    .with_detail("Normal after package upgrades — restart the service to load the new binary")
                    .subject(&format!("pid:{}", pid)),
            );
        } else {
            let sev = if util::is_temp_path(&exe) || util::has_hidden_component(&exe) { Severity::Danger } else { Severity::Warning };
            send(
                tx,
                Finding::new(sev, MODULE, "Deleted Binary", &format!("PID {} runs a deleted binary: {}", pid, exe))
                    .with_detail(&format!("Cmdline: {}\nThe file is gone from disk — common for dropped malware", cmd))
                    .subject(&format!("pid:{}", pid))
                    .artifact(&format!("/proc/{}/exe", pid)),
            );
        }
    }
}

fn ld_preload_check(tx: &Sender) {
    progress(tx, "Checking LD_PRELOAD / LD_AUDIT in every process environment...");
    let root = Root::live();
    for pid in util::proc_pids() {
        let data = match util::read_proc_bytes(format!("/proc/{}/environ", pid)) {
            Some(d) => d,
            None => continue,
        };
        for var in data.split(|&b| b == 0) {
            let var = String::from_utf8_lossy(var);
            for key in ["LD_PRELOAD=", "LD_AUDIT="] {
                if let Some(value) = var.strip_prefix(key) {
                    if value.trim().is_empty() {
                        continue;
                    }
                    let libs: Vec<&str> = value.split([':', ' ']).filter(|s| !s.is_empty()).collect();
                    let bad = libs.iter().any(|l| util::is_temp_path(l) || util::has_hidden_component(l) || pkg::owner(&root, l) == Ownership::NotOwned);
                    let sev = if bad || key == "LD_AUDIT=" { Severity::Danger } else { Severity::Warning };
                    let cat = if key == "LD_AUDIT=" { "LD_AUDIT" } else { "LD_PRELOAD" };
                    send(
                        tx,
                        Finding::new(sev, MODULE, cat, &format!("PID {} ({}) has {}{}", pid, procfs::comm(pid), key, value))
                            .with_detail(&format!(
                                "Process: {}\n{}",
                                procfs::read_cmdline(pid),
                                if bad {
                                    "Library is outside any package or in a temp/hidden path"
                                } else {
                                    "Library is package-owned (could be jemalloc/gtk-nocsd) — verify"
                                }
                            ))
                            .subject(&format!("pid:{}:{}", pid, cat)),
                    );
                }
            }
        }
    }
}

fn hidden_kernel_modules(cfg: &ScanConfig, tx: &Sender) {
    progress(tx, "Cross-checking kernel modules (/proc/modules vs /sys/module vs kallsyms)...");
    let proc_modules: HashSet<String> =
        util::read_proc("/proc/modules").map(|c| c.lines().filter_map(|l| l.split_whitespace().next().map(String::from)).collect()).unwrap_or_default();

    // loadable modules expose /sys/module/<m>/initstate; built-ins do not
    let mut hidden = Vec::new();
    for m in util::list_dir_raw("/sys/module").unwrap_or_default() {
        if std::path::Path::new(&format!("/sys/module/{}/initstate", m)).exists() && !proc_modules.contains(&m) {
            hidden.push(m);
        }
    }
    for m in &hidden {
        send(
            tx,
            Finding::new(Severity::Danger, MODULE, "Hidden Module", &format!("Kernel module '{}' is loaded (sysfs) but hidden from /proc/modules", m))
                .with_detail("Rootkits unlink themselves from the module list (list_del) to disappear from lsmod")
                .subject(&format!("module:{}", m)),
        );
    }

    // kallsyms owners: symbols tagged [mod] whose module isn't listed
    if cfg.is_root {
        if let Some(ks) = util::read_proc("/proc/kallsyms") {
            let mut owners: HashSet<String> = HashSet::new();
            for line in ks.lines() {
                if let Some(start) = line.rfind('[') {
                    if line.ends_with(']') {
                        owners.insert(line[start + 1..line.len() - 1].to_string());
                    }
                }
            }
            for o in owners {
                let pseudo = o.starts_with("__builtin") || o == "bpf" || o == "kprobes" || o == "ftrace" || o.starts_with("bpf_");
                if !pseudo && !proc_modules.contains(&o) && !hidden.contains(&o) {
                    send(
                        tx,
                        Finding::new(
                            Severity::Danger,
                            MODULE,
                            "Hidden Module",
                            &format!("kallsyms has symbols from module '{}' that is not in /proc/modules", o),
                        )
                        .with_detail("The module's code is resident in the kernel but it removed itself from the module list")
                        .subject(&format!("module:{}", o)),
                    );
                }
            }
        }
    }

    if hidden.is_empty() {
        send(
            tx,
            Finding::new(Severity::Safe, MODULE, "Kernel Modules", &format!("{} loaded modules, none hidden from /proc/modules", proc_modules.len()))
                .subject("modules"),
        );
    }

    // Signature check (kept separate from behaviour checks, so the README stays honest)
    let rootkit_names = [
        "diamorphine",
        "reptile",
        "bdvl",
        "jynx",
        "suterusu",
        "knark",
        "adore",
        "enyelkm",
        "azazel",
        "brootus",
        "nurupo",
        "khugepagefs",
        "kovid",
        "beurk",
        "vlany",
        "singularity",
        "puszek",
        "rkduck",
        "sutekh",
    ];
    let mut all: HashSet<&String> = proc_modules.iter().collect();
    all.extend(hidden.iter());
    for m in all {
        let lower = m.to_lowercase();
        if let Some(rk) = rootkit_names.iter().find(|rk| lower.contains(*rk)) {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Rootkit Signature", &format!("Kernel module '{}' matches known rootkit '{}'", m, rk))
                    .subject(&format!("sig:{}", m)),
            );
        }
    }
}

fn check_proc_anomalies(cfg: &ScanConfig, tx: &Sender) {
    progress(tx, "Checking /proc for anomalies...");
    if let Some(content) = util::read_proc("/proc/mounts") {
        for line in content.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() >= 4 && f[1] == "/proc" && f[3].contains("hidepid=") {
                send(
                    tx,
                    Finding::new(Severity::Info, MODULE, "Proc Mount", &format!("/proc mounted with hidepid ({}) — non-root views are limited", f[3]))
                        .subject("hidepid"),
                );
            }
            // something mounted over a /proc/<pid> directory hides that process
            if f.len() >= 2 {
                if let Some(rest) = f[1].strip_prefix("/proc/") {
                    if rest.split('/').next().map(|p| p.parse::<u32>().is_ok()).unwrap_or(false) {
                        send(
                            tx,
                            Finding::new(
                                Severity::Danger,
                                MODULE,
                                "Hidden Process",
                                &format!("A filesystem is mounted over {} — classic process-hiding trick", f[1]),
                            )
                            .with_detail(line)
                            .subject(&format!("mount:{}", f[1])),
                        );
                    }
                }
            }
        }
    }
    if cfg.is_root {
        let mut unreadable = Vec::new();
        for pid in util::proc_pids() {
            let status = format!("/proc/{}/status", pid);
            if std::path::Path::new(&status).exists() && util::read_proc(&status).is_none() {
                unreadable.push(pid);
            }
        }
        if !unreadable.is_empty() {
            send(
                tx,
                Finding::new(
                    Severity::Warning,
                    MODULE,
                    "Hidden Process",
                    &format!("{} process(es) have /proc entries that even root cannot read", unreadable.len()),
                )
                .with_detail(&format!("PIDs: {:?}", &unreadable[..unreadable.len().min(20)]))
                .subject("proc-unreadable"),
            );
        }
    }
}

pub fn scan(cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    hidden_pids(cfg, &tx);
    deleted_binaries(&tx);
    ld_preload_check(&tx);
    hidden_kernel_modules(cfg, &tx);
    check_proc_anomalies(cfg, &tx);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
