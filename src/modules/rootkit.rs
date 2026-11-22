use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const MODULE: &str = "ROOTKIT";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn hidden_pids(tx: &Sender) {
    progress(tx, "Checking for hidden PIDs (/proc vs ps)...");

    // Get PIDs from /proc
    let mut proc_pids = HashSet::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(pid) = name.parse::<u32>() {
                    proc_pids.insert(pid);
                }
            }
        }
    }

    // Get PIDs from ps
    let mut ps_pids = HashSet::new();
    if let Ok(output) = Command::new("ps").args(["-eo", "pid"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().skip(1) {
            if let Ok(pid) = line.trim().parse::<u32>() {
                ps_pids.insert(pid);
            }
        }
    }

    // PIDs in /proc but NOT in ps = possibly hidden by rootkit
    let hidden: Vec<u32> = proc_pids.difference(&ps_pids).copied().collect();
    // PIDs in ps but NOT in /proc = extremely suspicious
    let ghost: Vec<u32> = ps_pids.difference(&proc_pids).copied().collect();

    if !hidden.is_empty() {
        // Some difference is normal (race condition), but large numbers are suspicious
        if hidden.len() > 10 {
            send(tx, Finding::new(Severity::Warning, MODULE, "Hidden PIDs",
                &format!("{} PIDs in /proc but not in ps output — possible rootkit process hiding", hidden.len()))
                .with_detail(&format!("Sample PIDs: {:?}", &hidden[..std::cmp::min(20, hidden.len())])));
        }
    }

    if ghost.len() > 5 {
        // A few ghost PIDs are normal (race condition between ps and /proc reads)
        // Large numbers indicate actual /proc manipulation
        send(tx, Finding::new(Severity::Danger, MODULE, "Ghost PIDs",
            &format!("{} PIDs in ps but missing from /proc — rootkit may be manipulating /proc", ghost.len()))
            .with_detail(&format!("PIDs: {:?}", ghost)));
    } else if !ghost.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "PID Race",
            &format!("{} PIDs in ps but not in /proc (normal race condition)", ghost.len())));
    }

    if hidden.len() <= 10 && ghost.is_empty() {
        send(tx, Finding::new(Severity::Safe, MODULE, "PID Check",
            &format!("No hidden processes ({} /proc PIDs, {} ps PIDs)", proc_pids.len(), ps_pids.len())));
    }
}

fn deleted_binaries(tx: &Sender) {
    progress(tx, "Checking for processes running deleted binaries...");

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.parse::<u32>().is_err() {
                continue;
            }

            let exe_link = format!("/proc/{}/exe", name);
            if let Ok(target) = fs::read_link(&exe_link) {
                let target_str = target.to_string_lossy().to_string();
                if target_str.contains("(deleted)") {
                    let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", name))
                        .unwrap_or_default()
                        .replace('\0', " ");

                    send(tx, Finding::new(Severity::Danger, MODULE, "Deleted Binary",
                        &format!("PID {} running deleted binary: {}", name, target_str))
                        .with_detail(&format!("Cmdline: {}", cmdline.trim())));
                }
            }
        }
    }
}

fn ld_preload_check(tx: &Sender) {
    progress(tx, "Checking LD_PRELOAD across all processes...");

    // Global ld.so.preload
    if let Ok(content) = fs::read_to_string("/etc/ld.so.preload") {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            send(tx, Finding::new(Severity::Danger, MODULE, "LD Preload",
                "ld.so.preload has entries — global library injection active")
                .with_detail(&format!("Libraries: {}", trimmed)));
        }
    }

    // Check LD_PRELOAD in each process's environment
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.parse::<u32>().is_err() {
                continue;
            }

            let environ_path = format!("/proc/{}/environ", name);
            if let Ok(data) = fs::read(&environ_path) {
                let environ = String::from_utf8_lossy(&data);
                for var in environ.split('\0') {
                    if var.starts_with("LD_PRELOAD=") {
                        let value = &var[11..];
                        if !value.is_empty() {
                            let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", name))
                                .unwrap_or_default()
                                .replace('\0', " ");
                            send(tx, Finding::new(Severity::Danger, MODULE, "LD_PRELOAD",
                                &format!("PID {} has LD_PRELOAD set: {}", name, value))
                                .with_detail(&format!("Process: {}", cmdline.trim())));
                        }
                    }
                }
            }
        }
    }
}

fn hidden_kernel_modules(tx: &Sender) {
    progress(tx, "Checking for hidden kernel modules...");

    // /proc/modules vs /sys/module
    let mut proc_modules = HashSet::new();
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            if let Some(name) = line.split_whitespace().next() {
                proc_modules.insert(name.to_string());
            }
        }
    }

    let mut sys_modules = HashSet::new();
    if let Ok(entries) = fs::read_dir("/sys/module") {
        for entry in entries.flatten() {
            sys_modules.insert(entry.file_name().to_string_lossy().to_string());
        }
    }

    // Modules in /sys/module but NOT in /proc/modules could be hidden
    let hidden: Vec<&String> = sys_modules.difference(&proc_modules)
        .filter(|m| {
            // Some builtin modules appear in /sys/module but not /proc/modules — filter those
            let params = format!("/sys/module/{}/parameters", m);
            let sections = format!("/sys/module/{}/sections", m);
            Path::new(&sections).exists() || Path::new(&params).exists()
        })
        .collect();

    // Known rootkit module names
    let rootkit_names = ["diamorphine", "reptile", "bdvl", "jynx", "suterusu",
        "knark", "adore", "enyelkm", "azazel", "brootus", "nurupo",
        "khugepagefs", "kovid", "beurk", "vlany", "libprocesshider"];

    for module in proc_modules.iter().chain(sys_modules.iter()) {
        let lower = module.to_lowercase();
        for rk in &rootkit_names {
            if lower.contains(rk) {
                send(tx, Finding::new(Severity::Danger, MODULE, "Rootkit Module",
                    &format!("Known rootkit kernel module: {}", module)));
            }
        }
    }

    if !hidden.is_empty() && hidden.len() > 5 {
        send(tx, Finding::new(Severity::Info, MODULE, "Kernel Modules",
            &format!("{} in /proc/modules, {} in /sys/module ({} only in /sys)",
                proc_modules.len(), sys_modules.len(), hidden.len())));
    }
}

fn suspicious_kernel_state(tx: &Sender) {
    progress(tx, "Checking kernel taint and integrity flags...");

    // Check kernel taint flags
    if let Ok(taint) = fs::read_to_string("/proc/sys/kernel/tainted") {
        if let Ok(val) = taint.trim().parse::<u64>() {
            if val != 0 {
                let mut reasons = Vec::new();
                if val & 1 != 0 { reasons.push("proprietary module loaded"); }
                if val & 2 != 0 { reasons.push("module force loaded"); }
                if val & 4 != 0 { reasons.push("SMP kernel on non-SMP"); }
                if val & 8 != 0 { reasons.push("module force unloaded"); }
                if val & 16 != 0 { reasons.push("MCE occurred"); }
                if val & 32 != 0 { reasons.push("bad page found"); }
                if val & 64 != 0 { reasons.push("userspace taint requested"); }
                if val & 128 != 0 { reasons.push("kernel died/OOPS"); }
                if val & 256 != 0 { reasons.push("ACPI overridden"); }
                if val & 512 != 0 { reasons.push("warning occurred"); }
                if val & 4096 != 0 { reasons.push("out-of-tree module loaded"); }
                if val & 8192 != 0 { reasons.push("unsigned module loaded"); }

                let sev = if val & 8192 != 0 { Severity::Warning } else { Severity::Info };
                send(tx, Finding::new(sev, MODULE, "Kernel Taint",
                    &format!("Kernel tainted (flags={}): {}", val, reasons.join(", "))));
            }
        }
    }

    // Check if kprobes is active (could indicate monitoring/hooking)
    if let Ok(content) = fs::read_to_string("/sys/kernel/debug/kprobes/list") {
        let count = content.lines().count();
        if count > 0 {
            send(tx, Finding::new(Severity::Info, MODULE, "Kprobes",
                &format!("{} active kprobes — could be legitimate monitoring or rootkit hooks", count)));
        }
    }
}

fn check_proc_anomalies(tx: &Sender) {
    progress(tx, "Checking /proc for anomalies...");

    // Check if /proc is mounted with hidepid
    if let Ok(content) = fs::read_to_string("/proc/mounts") {
        for line in content.lines() {
            if line.starts_with("proc /proc") && line.contains("hidepid=") {
                send(tx, Finding::new(Severity::Info, MODULE, "Proc Mount",
                    &format!("proc mounted with hidepid: {}", line.trim())));
            }
        }
    }

    // Check for /proc/PID directories we can't read (may be cloaked)
    let mut unreadable = 0;
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.parse::<u32>().is_err() {
                continue;
            }
            let status = format!("/proc/{}/status", name);
            if Path::new(&status).exists() && fs::read_to_string(&status).is_err() {
                unreadable += 1;
            }
        }
    }

    if unreadable > 0 {
        send(tx, Finding::new(Severity::Info, MODULE, "Proc Access",
            &format!("{} process(es) with unreadable /proc/PID/status", unreadable)));
    }
}

pub fn scan(is_root: bool, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    hidden_pids(&tx);
    deleted_binaries(&tx);
    ld_preload_check(&tx);
    hidden_kernel_modules(&tx);

    if is_root {
        suspicious_kernel_state(&tx);
    }

    check_proc_anomalies(&tx);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
