use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::fs;
use std::process::Command;
use std::time::Instant;

const MODULE: &str = "LOGS";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn auth_log_analysis(tx: &Sender, is_root: bool) {
    progress(tx, "Analyzing authentication logs...");

    let log_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/auth.log.1"];

    for log_path in &log_paths {
        let content = match fs::read_to_string(log_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Failed login attempts
        let failed_passwords: Vec<&str> = content.lines()
            .filter(|l| l.contains("Failed password") || l.contains("authentication failure"))
            .collect();

        if failed_passwords.len() > 50 {
            // Extract unique IPs
            let mut ips = std::collections::HashSet::new();
            for line in &failed_passwords {
                if let Some(from_idx) = line.find("from ") {
                    let after = &line[from_idx + 5..];
                    if let Some(ip) = after.split_whitespace().next() {
                        ips.insert(ip.to_string());
                    }
                }
            }

            send(tx, Finding::new(Severity::Warning, MODULE, "Brute Force",
                &format!("{} failed login attempts from {} unique IPs in {}", failed_passwords.len(), ips.len(), log_path))
                .with_detail(&format!("Top IPs: {:?}", ips.iter().take(10).collect::<Vec<_>>())));
        }

        // Successful root logins
        let root_logins: Vec<&str> = content.lines()
            .filter(|l| l.contains("Accepted") && (l.contains("root") || l.contains("for root")))
            .collect();

        if !root_logins.is_empty() {
            send(tx, Finding::new(Severity::Info, MODULE, "Root Login",
                &format!("{} successful root login(s) in {}", root_logins.len(), log_path))
                .with_detail(&root_logins.last().map(|l| l.to_string()).unwrap_or_default()));
        }

        // Suspicious sudo commands
        let sudo_lines: Vec<&str> = content.lines()
            .filter(|l| l.contains("sudo") && l.contains("COMMAND="))
            .collect();

        let suspicious_sudo: Vec<&&str> = sudo_lines.iter()
            .filter(|l| {
                let lower = l.to_lowercase();
                lower.contains("/bin/bash") || lower.contains("/bin/sh") || lower.contains("chmod 777")
                    || lower.contains("passwd") || lower.contains("useradd")
                    || lower.contains("/etc/shadow") || lower.contains("visudo")
            })
            .collect();

        if !suspicious_sudo.is_empty() {
            send(tx, Finding::new(Severity::Info, MODULE, "Sudo",
                &format!("{} notable sudo commands in {}", suspicious_sudo.len(), log_path)));
        }

        // SSH key added
        let key_adds: Vec<&str> = content.lines()
            .filter(|l| l.contains("authorized_keys") || l.contains("Accepted publickey"))
            .collect();

        if !key_adds.is_empty() {
            send(tx, Finding::new(Severity::Info, MODULE, "SSH Auth",
                &format!("{} SSH key authentication events", key_adds.len())));
        }

        break; // Only process first found log
    }

    if !is_root {
        send(tx, Finding::new(Severity::Info, MODULE, "Auth Log",
            "Some log files may need root access for full analysis"));
    }
}

fn log_gap_detection(tx: &Sender) {
    progress(tx, "Checking for suspicious log gaps...");

    let log_files = ["/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log"];

    for log_path in &log_files {
        let content = match fs::read_to_string(log_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let lines: Vec<&str> = content.lines().collect();
        if lines.len() < 10 {
            continue;
        }

        // Check for timestamp gaps
        // Linux log format: "Nov 22 14:30:01 hostname ..."
        let mut prev_timestamp = String::new();
        let mut gaps = Vec::new();

        for line in &lines {
            if line.len() < 15 {
                continue;
            }
            let ts = &line[..15]; // "Nov 22 14:30:01"

            if !prev_timestamp.is_empty() && ts < &prev_timestamp {
                // Timestamp went backwards — log may have been tampered
                gaps.push(format!("{} -> {}", prev_timestamp, ts));
            }
            prev_timestamp = ts.to_string();
        }

        if !gaps.is_empty() {
            send(tx, Finding::new(Severity::Warning, MODULE, "Log Gap",
                &format!("{} timestamp anomalies in {}", gaps.len(), log_path))
                .with_detail(&format!("First gap: {}", gaps[0])));
        }

        // Check if log file is suspiciously small
        if let Ok(meta) = fs::metadata(log_path) {
            if meta.len() < 1000 && log_path.contains("auth") {
                send(tx, Finding::new(Severity::Warning, MODULE, "Truncated Log",
                    &format!("{} is suspiciously small ({} bytes) — may have been wiped",
                        log_path, meta.len())));
            }
        }
    }
}

fn history_analysis(tx: &Sender) {
    progress(tx, "Analyzing shell history files...");

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    let history_files = [
        (".bash_history", "bash"),
        (".zsh_history", "zsh"),
        (".python_history", "python"),
        (".mysql_history", "mysql"),
        (".psql_history", "psql"),
    ];

    for (file, shell) in &history_files {
        let path = format!("{}/{}", home, file);

        // Check if history is symlinked to /dev/null
        if let Ok(target) = fs::read_link(&path) {
            let target_str = target.to_string_lossy().to_string();
            if target_str == "/dev/null" || target_str.contains("/dev/null") {
                send(tx, Finding::new(Severity::Danger, MODULE, "History Evasion",
                    &format!("{} history symlinked to /dev/null", shell))
                    .with_detail(&format!("{} -> {}", path, target_str)));
                continue;
            }
        }

        if let Ok(content) = fs::read_to_string(&path) {
            if content.is_empty() {
                send(tx, Finding::new(Severity::Warning, MODULE, "Empty History",
                    &format!("{} history file is empty — may have been cleared", shell)));
                continue;
            }

            // Look for suspicious commands in history
            let suspicious = [
                "history -c", "history -w /dev/null", "unset HISTFILE",
                "export HISTSIZE=0", "export HISTFILESIZE=0",
                "shred", "rm -rf /var/log", ">/var/log/",
                "cat /etc/shadow", "cat /etc/passwd | grep",
                "nc -e", "ncat -e", "/dev/tcp/",
                "base64 -d", "curl.*|.*bash", "wget.*|.*sh",
            ];

            for line in content.lines() {
                let lower = line.to_lowercase().trim().to_string();
                for pat in &suspicious {
                    if lower.contains(pat) {
                        send(tx, Finding::new(Severity::Warning, MODULE, "Suspicious Cmd",
                            &format!("{} history: {}", shell, truncate(&lower, 80)))
                            .with_detail(&format!("Pattern: {}", pat)));
                        break;
                    }
                }
            }
        }
    }
}

fn wtmp_btmp_analysis(tx: &Sender) {
    progress(tx, "Analyzing login records (wtmp/btmp)...");

    // last command for recent logins
    if let Ok(output) = Command::new("last").args(["-n", "50", "-i"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with("wtmp") && !l.starts_with("reboot"))
            .collect();

        if !lines.is_empty() {
            send(tx, Finding::new(Severity::Info, MODULE, "Login Records",
                &format!("{} recent login records", lines.len())));
        }
    }

    // lastb for failed logins (needs root)
    if let Ok(output) = Command::new("lastb").args(["-n", "50", "-i"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let lines: Vec<&str> = stdout.lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with("btmp"))
            .collect();

        if lines.len() > 20 {
            send(tx, Finding::new(Severity::Warning, MODULE, "Failed Logins",
                &format!("{} failed login attempts in btmp", lines.len())));
        }
    }
}

fn journald_analysis(tx: &Sender) {
    progress(tx, "Checking journald for security events...");

    // Look for segfaults (could indicate exploitation)
    if let Ok(output) = Command::new("journalctl")
        .args(["--since", "7 days ago", "--no-pager", "-q",
               "--grep", "segfault|exploit|overflow|injection"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let count = stdout.lines().count();
        if count > 0 {
            send(tx, Finding::new(Severity::Info, MODULE, "Segfaults",
                &format!("{} crash/security events in journal (7 days)", count)));
        }
    }

    // Check for service failures
    if let Ok(output) = Command::new("systemctl")
        .args(["--failed", "--no-legend", "--no-pager"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let failed: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
        if !failed.is_empty() {
            send(tx, Finding::new(Severity::Info, MODULE, "Failed Services",
                &format!("{} failed systemd service(s)", failed.len()))
                .with_detail(&failed.iter().take(5).copied().collect::<Vec<_>>().join("\n")));
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max]) } else { s.to_string() }
}

pub fn scan(is_root: bool, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    auth_log_analysis(&tx, is_root);
    log_gap_detection(&tx);
    history_analysis(&tx);
    wtmp_btmp_analysis(&tx);
    journald_analysis(&tx);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
