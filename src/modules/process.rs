use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::fs;
use std::time::Instant;

const MODULE: &str = "PROCESS";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

#[allow(dead_code)]
struct ProcInfo {
    pid: u32,
    name: String,
    cmdline: String,
    ppid: u32,
    uid: u32,
    exe: String,
}

fn read_procs() -> Vec<ProcInfo> {
    let mut procs = Vec::new();

    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return procs,
    };

    for entry in entries.flatten() {
        let pid_str = entry.file_name().to_string_lossy().to_string();
        let pid = match pid_str.parse::<u32>() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let status = match fs::read_to_string(format!("/proc/{}/status", pid)) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut name = String::new();
        let mut ppid = 0u32;
        let mut uid = 0u32;

        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Name:\t") {
                name = val.to_string();
            } else if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.trim().parse().unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Uid:\t") {
                uid = val.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
        }

        let cmdline = fs::read_to_string(format!("/proc/{}/cmdline", pid))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();

        let exe = fs::read_link(format!("/proc/{}/exe", pid))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        procs.push(ProcInfo { pid, name, cmdline, ppid, uid, exe });
    }

    procs
}

fn reverse_shell_detection(tx: &Sender, procs: &[ProcInfo]) {
    progress(tx, "Checking for reverse shell patterns...");

    let shell_names = ["bash", "sh", "zsh", "dash", "fish", "ksh", "csh"];
    let web_server_names = ["apache", "nginx", "httpd", "lighttpd", "caddy", "node", "python", "ruby", "php", "java", "tomcat"];

    for proc in procs {
        let name_lower = proc.name.to_lowercase();
        let cmd_lower = proc.cmdline.to_lowercase();

        // Shell spawned by web server = potential reverse shell
        if shell_names.contains(&name_lower.as_str()) {
            if let Some(parent) = procs.iter().find(|p| p.pid == proc.ppid) {
                let parent_lower = parent.name.to_lowercase();
                if web_server_names.iter().any(|w| parent_lower.contains(w)) {
                    send(tx, Finding::new(Severity::Danger, MODULE, "Reverse Shell",
                        &format!("Shell '{}' (PID {}) spawned by web server '{}' (PID {})",
                            proc.name, proc.pid, parent.name, parent.pid))
                        .with_detail(&format!("Cmdline: {}\nParent: {}", proc.cmdline, parent.cmdline)));
                }
            }
        }

        // Direct reverse shell patterns in cmdline
        let rev_patterns = [
            "/dev/tcp/", "/dev/udp/", "bash -i", "nc -e", "ncat -e",
            "mkfifo", "socat exec", "openssl.*connect",
            "python -c.*import.*socket", "python3 -c.*import.*socket",
            "perl -e.*socket", "ruby -rsocket",
            "php -r.*fsockopen", "lua.*socket",
        ];

        for pattern in &rev_patterns {
            if cmd_lower.contains(pattern) {
                send(tx, Finding::new(Severity::Danger, MODULE, "Reverse Shell",
                    &format!("PID {} — reverse shell pattern: {}", proc.pid, pattern))
                    .with_detail(&format!("Name: {}\nCmdline: {}", proc.name, proc.cmdline)));
                break;
            }
        }
    }
}

fn crypto_miner_detection(tx: &Sender, procs: &[ProcInfo]) {
    progress(tx, "Checking for crypto miners...");

    let miner_names = ["xmrig", "minerd", "minergate", "cpuminer", "ethminer",
        "cgminer", "bfgminer", "ccminer", "nheqminer", "cryptonight"];

    let miner_args = ["stratum+tcp", "stratum+ssl", "--coin", "--donate-level",
        "-o pool.", "--algo=", "randomx", "cryptonight", "kawpow"];

    for proc in procs {
        let name_lower = proc.name.to_lowercase();
        let cmd_lower = proc.cmdline.to_lowercase();

        for miner in &miner_names {
            if name_lower.contains(miner) || cmd_lower.contains(miner) {
                send(tx, Finding::new(Severity::Danger, MODULE, "Crypto Miner",
                    &format!("PID {} — crypto miner detected: {}", proc.pid, proc.name))
                    .with_detail(&format!("Cmdline: {}", proc.cmdline)));
                break;
            }
        }

        for arg in &miner_args {
            if cmd_lower.contains(arg) {
                send(tx, Finding::new(Severity::Danger, MODULE, "Crypto Miner",
                    &format!("PID {} — mining pool argument: {}", proc.pid, arg))
                    .with_detail(&format!("Name: {}\nCmdline: {}", proc.name, proc.cmdline)));
                break;
            }
        }
    }
}

fn suspicious_process_patterns(tx: &Sender, procs: &[ProcInfo]) {
    progress(tx, "Checking for suspicious process patterns...");

    for proc in procs {
        let cmd_lower = proc.cmdline.to_lowercase();
        let name_lower = proc.name.to_lowercase();

        // Process running from /tmp, /dev/shm, /var/tmp
        if proc.exe.starts_with("/tmp/") || proc.exe.starts_with("/dev/shm/")
            || proc.exe.starts_with("/var/tmp/") || proc.exe.starts_with("/run/") {
            send(tx, Finding::new(Severity::Warning, MODULE, "Temp Exec",
                &format!("PID {} running from suspicious location: {}", proc.pid, proc.exe))
                .with_detail(&format!("Name: {}\nCmdline: {}", proc.name, proc.cmdline)));
        }

        // Base64 decode in cmdline
        if cmd_lower.contains("base64") && (cmd_lower.contains("-d") || cmd_lower.contains("--decode")) {
            send(tx, Finding::new(Severity::Warning, MODULE, "Obfuscation",
                &format!("PID {} — base64 decode in command line", proc.pid))
                .with_detail(&format!("Cmdline: {}", proc.cmdline)));
        }

        // Hidden process name (starts with . or has only spaces)
        if name_lower.starts_with('.') || name_lower.starts_with(' ') || name_lower == "" {
            send(tx, Finding::new(Severity::Warning, MODULE, "Hidden Name",
                &format!("PID {} has hidden/empty process name: '{}'", proc.pid, proc.name))
                .with_detail(&format!("Exe: {}\nCmdline: {}", proc.exe, proc.cmdline)));
        }

        // Process name mimicking system processes but from wrong path
        let system_mimics = [
            ("sshd", "/usr/sbin/sshd"),
            ("cron", "/usr/sbin/cron"),
            ("systemd", "/lib/systemd/systemd"),
            ("dbus-daemon", "/usr/bin/dbus-daemon"),
            ("rsyslogd", "/usr/sbin/rsyslogd"),
        ];

        for (expected_name, expected_path) in &system_mimics {
            if name_lower == *expected_name && !proc.exe.is_empty()
                && !proc.exe.starts_with(expected_path) && !proc.exe.contains("(deleted)") {
                send(tx, Finding::new(Severity::Warning, MODULE, "Name Spoof",
                    &format!("PID {} — '{}' running from unexpected path", proc.pid, proc.name))
                    .with_detail(&format!("Expected: {}\nActual: {}", expected_path, proc.exe)));
            }
        }
    }
}

fn namespace_detection(tx: &Sender) {
    progress(tx, "Checking for hidden namespaces...");

    // Check for processes in non-default namespaces
    let init_ns = fs::read_link("/proc/1/ns/pid")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    if init_ns.is_empty() {
        return;
    }

    let mut different_ns = Vec::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.parse::<u32>().is_err() || name == "1" {
                continue;
            }

            let ns_path = format!("/proc/{}/ns/pid", name);
            if let Ok(ns) = fs::read_link(&ns_path) {
                let ns_str = ns.to_string_lossy().to_string();
                if ns_str != init_ns {
                    different_ns.push((name, ns_str));
                }
            }
        }
    }

    if !different_ns.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "Namespaces",
            &format!("{} process(es) in non-default PID namespaces (containers/sandboxes)", different_ns.len())));
    }
}

pub fn scan(tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    let procs = read_procs();
    progress(&tx, &format!("Enumerated {} processes", procs.len()));

    reverse_shell_detection(&tx, &procs);
    crypto_miner_detection(&tx, &procs);
    suspicious_process_patterns(&tx, &procs);
    namespace_detection(&tx);

    send(&tx, Finding::new(Severity::Info, MODULE, "Summary",
        &format!("{} processes analyzed", procs.len())));

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
