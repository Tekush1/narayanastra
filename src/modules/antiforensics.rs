use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const MODULE: &str = "ANTIFOR";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn has_executable_files(dir: &Path) -> bool {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Ok(data) = fs::read(&path) {
            if data.len() >= 4 && &data[..4] == b"\x7fELF" {
                return true;
            }
            if data.len() >= 2 && &data[..2] == b"MZ" {
                return true;
            }
        }
    }
    false
}

fn timestomping_check(tx: &Sender) {
    progress(tx, "Checking for timestamp manipulation (timestomping)...");

    // Only check canonical paths — /bin, /sbin, /lib are symlinks to /usr/* on modern distros
    let check_dirs = ["/usr/bin", "/usr/sbin", "/usr/lib"];

    let mut stomped = Vec::new();

    for dir in &check_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            if let Ok(meta) = path.metadata() {
                let mtime = meta.mtime();
                let now = chrono::Local::now().timestamp();

                // Only flag truly suspicious cases:
                // 1. mtime in the future (clear manipulation)
                if mtime > now + 86400 {
                    stomped.push(path.to_string_lossy().to_string());
                    send(tx, Finding::new(Severity::Danger, MODULE, "Timestomp",
                        &format!("Future-dated file: {}", path.display()))
                        .with_detail(&format!("mtime is {} seconds in the future", mtime - now)));
                }

                // 2. mtime set to epoch 0 or very old (pre-2000) for a recently installed binary
                // Note: We do NOT flag normal "mtime before ctime" because package managers
                // preserve the original build timestamp as mtime, while ctime reflects install time.
                // This is completely normal (e.g., lzop built 2020, installed 2026).
                if mtime < 946684800 && mtime > 0 {
                    // mtime before year 2000 — suspicious for a system binary
                    let ctime = meta.ctime();
                    if ctime > now - 86400 * 365 {
                        stomped.push(path.to_string_lossy().to_string());
                        send(tx, Finding::new(Severity::Warning, MODULE, "Timestomp",
                            &format!("Binary with pre-2000 timestamp: {}", path.display()))
                            .with_detail(&format!("mtime={} (pre-2000), ctime={} (recent) — likely backdated", mtime, ctime)));
                    }
                }
            }
        }
    }

    if stomped.is_empty() {
        send(tx, Finding::new(Severity::Safe, MODULE, "Timestamps",
            "No timestamp anomalies in system binaries"));
    }
}

fn hidden_files_check(tx: &Sender) {
    progress(tx, "Scanning for suspicious hidden files and directories...");

    let check_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/usr/lib", "/usr/share",
                      "/opt", "/var/lib"];

    let home = std::env::var("HOME").unwrap_or_default();

    for dir in &check_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();

            // Triple dot directory (classic hiding technique)
            if name == "..." || name == ".. " || name == ". " {
                send(tx, Finding::new(Severity::Danger, MODULE, "Hidden Dir",
                    &format!("Suspicious directory name '{}' in {}", name, dir))
                    .with_detail("Triple-dot or space-dot directories are classic rootkit hiding spots"));
            }

            // Unicode tricks (zero-width characters)
            if name.contains('\u{200b}') || name.contains('\u{200c}')
                || name.contains('\u{200d}') || name.contains('\u{feff}')
                || name.contains('\u{00a0}') {
                send(tx, Finding::new(Severity::Danger, MODULE, "Unicode Hide",
                    &format!("File/dir with Unicode hiding characters: {} in {}", name, dir)));
            }

            if name.starts_with('.') && name != "." && name != ".." {
                let path = entry.path();

                // Behavior-based: check what's INSIDE, not the name
                if path.is_file() {
                    if let Ok(data) = fs::read(&path) {
                        // Hidden ELF binary in temp dir = very suspicious
                        if data.len() >= 4 && &data[..4] == b"\x7fELF" {
                            send(tx, Finding::new(Severity::Danger, MODULE, "Hidden Binary",
                                &format!("ELF binary hidden in {}: {}", dir, name))
                                .with_detail(&format!("Size: {} bytes", data.len())));
                        }
                        // Hidden PE binary
                        else if data.len() >= 2 && &data[..2] == b"MZ" {
                            send(tx, Finding::new(Severity::Danger, MODULE, "Hidden Binary",
                                &format!("PE executable hidden in {}: {}", dir, name)));
                        }
                        // Hidden script with suspicious content
                        else if data.len() > 2 && data[0] == b'#' && data[1] == b'!' {
                            let script = String::from_utf8_lossy(&data[..std::cmp::min(1024, data.len())]).to_lowercase();
                            let bad_patterns = ["curl", "wget", "nc ", "/dev/tcp", "base64", "eval", "exec"];
                            if bad_patterns.iter().any(|p| script.contains(p)) {
                                send(tx, Finding::new(Severity::Warning, MODULE, "Hidden Script",
                                    &format!("Suspicious hidden script in {}: {}", dir, name))
                                    .with_detail(&format!("Size: {} bytes", data.len())));
                            }
                        }
                    }
                }

                // Hidden dir with executables inside
                if path.is_dir() {
                    let has_executables = has_executable_files(&path);
                    if has_executables {
                        send(tx, Finding::new(Severity::Warning, MODULE, "Hidden Dir",
                            &format!("Hidden directory with executables in {}: {}", dir, name))
                            .with_detail(&format!("Path: {}", path.display())));
                    }
                }
            }
        }
    }

    // Check home dotdirs — no whitelist, check for DANGEROUS behavior instead
    if let Ok(entries) = fs::read_dir(&home) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with('.') || name == "." || name == ".." {
                continue;
            }
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Only flag dotdirs that show actual malicious behavior:

            // 1. Contains executable files (not scripts, actual ELF/PE binaries)
            if let Ok(sub_entries) = fs::read_dir(&path) {
                for sub in sub_entries.flatten() {
                    let sub_path = sub.path();
                    if !sub_path.is_file() {
                        continue;
                    }
                    if let Ok(data) = fs::read(&sub_path) {
                        if data.len() >= 4 && &data[..4] == b"\x7fELF" {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(meta) = sub_path.metadata() {
                                if meta.permissions().mode() & 0o111 != 0 {
                                    send(tx, Finding::new(Severity::Warning, MODULE, "Hidden Executable",
                                        &format!("ELF binary in hidden home dir: {}/{}", name, sub.file_name().to_string_lossy()))
                                        .with_detail(&format!("Path: {}", sub_path.display())));
                                }
                            }
                        }
                    }
                }
            }

            // 2. Recently created with suspicious name patterns
            if name.contains("..") || name.contains("  ") || name.len() == 1 {
                send(tx, Finding::new(Severity::Warning, MODULE, "Suspicious Dotdir",
                    &format!("Suspicious hidden directory name in home: '{}'", name)));
            }
        }
    }
}

fn log_tampering_check(tx: &Sender) {
    progress(tx, "Checking for log tampering indicators...");

    // Check if log files have been truncated (size 0 but exist)
    let important_logs = [
        "/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log",
        "/var/log/daemon.log", "/var/log/messages",
    ];

    for log_path in &important_logs {
        if let Ok(meta) = fs::metadata(log_path) {
            if meta.len() == 0 {
                send(tx, Finding::new(Severity::Danger, MODULE, "Wiped Log",
                    &format!("Log file is empty (0 bytes): {}", log_path))
                    .with_detail("Critical log file has been wiped"));
            }
        }
    }

    // Check /var/log permissions
    if let Ok(entries) = fs::read_dir("/var/log") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Ok(meta) = path.metadata() {
                    // Log files owned by non-root/non-syslog
                    let uid = meta.uid();
                    if uid != 0 && uid != 104 && uid != 101 { // root, syslog, _apt
                        let name = entry.file_name().to_string_lossy().to_string();
                        if name.ends_with(".log") || name.ends_with(".log.1") {
                            send(tx, Finding::new(Severity::Warning, MODULE, "Log Owner",
                                &format!("Log file owned by uid {}: {}", uid, path.display())));
                        }
                    }
                }
            }
        }
    }
}

fn pam_backdoor_check(tx: &Sender) {
    progress(tx, "Checking for PAM backdoors...");

    // Check if pam_unix.so has been modified — resolve symlinks first
    let pam_paths = [
        "/lib/x86_64-linux-gnu/security/pam_unix.so",
        "/lib64/security/pam_unix.so",
        "/usr/lib/x86_64-linux-gnu/security/pam_unix.so",
        "/usr/lib64/security/pam_unix.so",
    ];

    for pam_path in &pam_paths {
        if !Path::new(pam_path).exists() {
            continue;
        }

        // Resolve symlinks (/lib -> /usr/lib) before checking dpkg
        let real_path = fs::canonicalize(pam_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| pam_path.to_string());

        let mut is_owned = false;
        // Try both the original and resolved path
        for check_path in &[pam_path.to_string(), real_path.clone()] {
            if let Ok(output) = Command::new("dpkg").args(["-S", check_path.as_str()]).output() {
                if output.status.success() {
                    is_owned = true;
                    break;
                }
            }
        }

        if !is_owned {
            send(tx, Finding::new(Severity::Danger, MODULE, "PAM Backdoor",
                &format!("PAM module not owned by any package: {}", real_path))
                .with_detail("This PAM module may have been replaced with a backdoored version"));
        }

        // Check for REAL pam_permit backdoors in PAM config
        // Standard Debian config has pam_permit.so at the end AFTER pam_deny.so — that's safe.
        // A backdoor would be pam_permit.so as a primary auth (before pam_deny or as sufficient).
        let pam_configs = ["/etc/pam.d/common-auth", "/etc/pam.d/sshd", "/etc/pam.d/sudo"];
        for config in &pam_configs {
            if let Ok(content) = fs::read_to_string(config) {
                let active_lines: Vec<&str> = content.lines()
                    .filter(|l| !l.trim().starts_with('#') && !l.trim().is_empty())
                    .collect();

                let has_deny = active_lines.iter().any(|l| l.contains("pam_deny.so"));
                let has_unix_auth = active_lines.iter().any(|l| l.contains("pam_unix.so") && l.contains("auth"));

                for line in &active_lines {
                    if line.contains("pam_permit.so") && line.contains("auth") {
                        // pam_permit after pam_deny + pam_unix is standard Debian config
                        // pam_permit as "sufficient" or without pam_deny is a backdoor
                        if line.contains("sufficient") {
                            send(tx, Finding::new(Severity::Danger, MODULE, "PAM Backdoor",
                                &format!("pam_permit.so as SUFFICIENT in: {}", config))
                                .with_detail("This bypasses all password checks!"));
                        } else if !has_deny || !has_unix_auth {
                            send(tx, Finding::new(Severity::Danger, MODULE, "PAM Backdoor",
                                &format!("pam_permit.so without proper auth chain in: {}", config))
                                .with_detail("Missing pam_deny.so or pam_unix.so — authentication may be bypassed"));
                        }
                        // If pam_deny and pam_unix both present with pam_permit at end = standard, skip
                    }
                }
            }
        }
        break;
    }
}

fn suspicious_environment(tx: &Sender) {
    progress(tx, "Checking for suspicious environment variables...");

    let suspicious_vars = [
        ("LD_PRELOAD", "Library injection"),
        ("LD_LIBRARY_PATH", "Library path override"),
        ("LD_AUDIT", "Library auditing hook"),
        ("LD_DEBUG", "Library debug mode"),
        ("PROMPT_COMMAND", "Command executed before every prompt"),
        ("BASH_ENV", "Script executed on bash startup"),
        ("ENV", "Script executed on sh startup"),
    ];

    for (var, desc) in &suspicious_vars {
        if let Ok(val) = std::env::var(var) {
            if !val.is_empty() {
                let sev = if *var == "LD_PRELOAD" || *var == "LD_AUDIT" {
                    Severity::Danger
                } else if *var == "PROMPT_COMMAND" || *var == "BASH_ENV" {
                    Severity::Warning
                } else {
                    Severity::Info
                };

                send(tx, Finding::new(sev, MODULE, "Env Var",
                    &format!("{} is set: {} — {}", var, truncate(&val, 60), desc)));
            }
        }
    }
}

fn rootkit_artifacts(tx: &Sender) {
    progress(tx, "Checking for known rootkit artifacts...");

    let rootkit_files = [
        // Diamorphine
        "/proc/diamorphine",
        // Reptile
        "/proc/reptile",
        "/dev/.reptile",
        // Jynx2
        "/usr/lib/jynx2",
        // Azazel
        "/var/tmp/.azazel",
        // bdvl
        "/etc/ld.so.preload",
        // Common hiding spots
        "/dev/.hid", "/dev/.sd0", "/dev/.sd1",
        "/usr/lib/.hid", "/usr/share/.hid",
        "/tmp/.font-unix/.x", "/tmp/.ICE-unix/.x",
        "/tmp/.X25-unix/.x",
    ];

    for path in &rootkit_files {
        if path == &"/etc/ld.so.preload" {
            continue; // Already checked in rootkit module
        }
        if Path::new(path).exists() {
            send(tx, Finding::new(Severity::Danger, MODULE, "Rootkit File",
                &format!("Known rootkit artifact found: {}", path)));
        }
    }

    // Check for processes hiding in /proc by looking for gaps
    // This is different from the PID comparison — look for /proc/PID that exist but can't be read
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.parse::<u32>().is_err() {
                continue;
            }
            let status_path = format!("/proc/{}/status", name);
            let cmdline_path = format!("/proc/{}/cmdline", name);

            // Can see the directory but not status or cmdline = suspicious
            if Path::new(&status_path).exists() {
                if fs::read_to_string(&status_path).is_err()
                    && fs::read_to_string(&cmdline_path).is_err() {
                    send(tx, Finding::new(Severity::Warning, MODULE, "Hidden Process",
                        &format!("PID {} — /proc entry exists but cannot read status/cmdline", name)));
                }
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max]) } else { s.to_string() }
}

pub fn scan(tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    timestomping_check(&tx);
    hidden_files_check(&tx);
    log_tampering_check(&tx);
    pam_backdoor_check(&tx);
    suspicious_environment(&tx);
    rootkit_artifacts(&tx);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
