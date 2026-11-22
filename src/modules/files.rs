use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

const MODULE: &str = "FILES";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn suid_sgid_scan(tx: &Sender) {
    progress(tx, "Scanning for SUID/SGID binaries...");

    // Known-safe SUID/SGID binary names (basename matching — handles /bin vs /usr/bin symlinks)
    let known_suid_names: std::collections::HashSet<&str> = [
        "sudo", "sudoedit", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
        "mount", "umount", "fusermount", "fusermount3", "pkexec", "crontab", "at",
        "ping", "ping6", "Xorg", "X", "pppd", "sg", "newuidmap", "newgidmap",
        "chage", "expiry",
        // SSH/network
        "ssh-agent", "ssh-keysign",
        // Mail
        "sendmail", "mailq", "newaliases", "exim", "exim4", "rsmtp", "rmail", "runq",
        "postdrop", "postqueue",
        // NFS/CIFS
        "mount.nfs", "mount.nfs4", "umount.nfs", "umount.nfs4",
        "mount.cifs", "mount.smb3",
        // NTFS
        "ntfs-3g", "mount.ntfs-3g", "mount.ntfs",
        // PAM
        "unix_chkpwd",
        // Misc system
        "locate", "plocate", "mlocate", "dotlockfile",
        "dbus-daemon-launch-helper", "polkit-agent-helper-1",
        "snap-confine", "chrome-sandbox", "chromium-sandbox",
        // Kali/pentest tools
        "kismet_cap_linux_wifi", "kismet_cap_linux_bluetooth",
        "kismet_cap_nrf_mousejack", "kismet_cap_hak5_wifi_coconut",
        "kismet_cap_nrf_51822", "kismet_cap_nrf_52840",
        "kismet_cap_ti_cc_2531", "kismet_cap_ti_cc_2540",
        "kismet_cap_ubertooth_one", "kismet_cap_nxp_kw41z",
        "kismet_cap_rz_killerbee",
        // RSH
        "rsh", "rlogin", "rsh-redone-rsh", "rsh-redone-rlogin", "rcp",
    ].iter().copied().collect();

    // Only scan canonical paths, skip symlink duplicates
    let search_dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
        "/usr/lib", "/usr/libexec"];

    let mut total_suid = 0;
    let mut suspicious_count = 0;

    // Collect non-whitelisted SUID files, then batch-check with dpkg
    let mut to_check: Vec<(String, String, u32, u32)> = Vec::new(); // (path, flag, mode, uid)

    for dir in &search_dirs {
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
                let mode = meta.permissions().mode();
                let is_suid = mode & 0o4000 != 0;
                let is_sgid = mode & 0o2000 != 0;

                if is_suid || is_sgid {
                    total_suid += 1;
                    let basename = path.file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_default();

                    if !known_suid_names.contains(basename.as_str()) {
                        let flag = if is_suid { "SUID" } else { "SGID" };
                        to_check.push((
                            path.to_string_lossy().to_string(),
                            flag.to_string(),
                            mode,
                            meta.uid(),
                        ));
                    }
                }
            }
        }
    }

    // Batch dpkg check for unknowns
    for (path_str, flag, mode, uid) in &to_check {
        if !is_package_owned(path_str) {
            suspicious_count += 1;
            send(tx, Finding::new(Severity::Warning, MODULE, flag,
                &format!("Unexpected {} binary (not in any package): {}", flag, path_str))
                .with_detail(&format!("Mode: {:o}, Owner: uid={}", mode, uid)));
        }
    }

    if suspicious_count == 0 {
        send(tx, Finding::new(Severity::Safe, MODULE, "SUID/SGID",
            &format!("{} SUID/SGID binaries found — all belong to known packages", total_suid)));
    } else {
        send(tx, Finding::new(Severity::Info, MODULE, "SUID/SGID",
            &format!("{} total SUID/SGID, {} suspicious (not in any package)", total_suid, suspicious_count)));
    }
}

fn is_package_owned(path: &str) -> bool {
    // dpkg -S to check if file belongs to a package
    if let Ok(output) = Command::new("dpkg").args(["-S", path]).output() {
        return output.status.success();
    }
    // Try rpm
    if let Ok(output) = Command::new("rpm").args(["-qf", path]).output() {
        return output.status.success();
    }
    false
}

fn package_integrity(tx: &Sender, is_root: bool) {
    if !is_root {
        progress(tx, "Package integrity check skipped (needs root for full scan)...");
        return;
    }

    progress(tx, "Verifying package integrity (dpkg --verify)...");

    // Spawn with timeout — dpkg --verify can take minutes on large systems
    let mut child = match Command::new("dpkg").args(["--verify"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn() {
        Ok(c) => c,
        Err(_) => return,
    };

    // Wait max 30 seconds
    let timeout = std::time::Duration::from_secs(30);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    send(tx, Finding::new(Severity::Info, MODULE, "Pkg Integrity",
                        "dpkg --verify timed out (>30s) — system has many packages, skipping"));
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(_) => return,
        }
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(_) => return,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{}{}", stdout, stderr);

    let mut modified = Vec::new();
    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("5") && trimmed.len() > 10 {
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let file_path = parts[1].trim();
                if file_path.starts_with("/etc/") {
                    continue;
                }
                if file_path.starts_with("/usr/bin/") || file_path.starts_with("/usr/sbin/")
                    || file_path.starts_with("/bin/") || file_path.starts_with("/sbin/")
                    || file_path.contains(".so") {
                    modified.push(file_path.to_string());
                }
            }
        }
    }

    if modified.is_empty() {
        send(tx, Finding::new(Severity::Safe, MODULE, "Pkg Integrity",
            "System binaries match package checksums"));
    } else {
        for path in &modified {
            send(tx, Finding::new(Severity::Danger, MODULE, "Tampered Binary",
                &format!("Binary modified from package version: {}", path))
                .with_detail("File checksum doesn't match installed package"));
        }
    }
}

fn devshm_check(tx: &Sender) {
    progress(tx, "Checking /dev/shm for executables...");

    if let Ok(entries) = fs::read_dir("/dev/shm") {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = path.metadata() {
                let mode = meta.permissions().mode();
                if mode & 0o111 != 0 && path.is_file() {
                    send(tx, Finding::new(Severity::Danger, MODULE, "/dev/shm",
                        &format!("Executable in shared memory: {}", path.display()))
                        .with_detail(&format!("Size: {} bytes, Mode: {:o}", meta.len(), mode)));
                }
            }
        }
    }

    // Also check /run and /var/run
    for dir in &["/run/user", "/var/run"] {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(meta) = path.metadata() {
                        let mode = meta.permissions().mode();
                        if mode & 0o111 != 0 {
                            let ext = path.extension().map(|e| e.to_string_lossy().to_string()).unwrap_or_default();
                            if ext != "pid" && ext != "lock" {
                                send(tx, Finding::new(Severity::Info, MODULE, "Tmp Exec",
                                    &format!("Executable in runtime dir: {}", path.display())));
                            }
                        }
                    }
                }
            }
        }
    }
}

fn world_writable_check(tx: &Sender) {
    progress(tx, "Checking for world-writable files in sensitive locations...");

    let sensitive_dirs = ["/etc", "/usr/bin", "/usr/sbin", "/usr/lib"];

    for dir in &sensitive_dirs {
        if let Ok(output) = Command::new("find")
            .args([dir, "-maxdepth", "2", "-perm", "-o+w", "-type", "f"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    send(tx, Finding::new(Severity::Warning, MODULE, "World-Writable",
                        &format!("World-writable file: {}", trimmed)));
                }
            }
        }
    }
}

fn immutable_check(tx: &Sender) {
    progress(tx, "Checking for suspicious immutable files...");

    // Rootkits sometimes set immutable flag on their files
    let check_dirs = ["/tmp", "/var/tmp", "/dev/shm", "/usr/bin", "/usr/sbin"];

    for dir in &check_dirs {
        if !Path::new(dir).exists() {
            continue;
        }

        if let Ok(output) = Command::new("lsattr").args(["-Ra", dir]).output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // 'i' flag = immutable
                if line.contains("----i") || (line.len() > 4 && line.chars().nth(4) == Some('i')) {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        let file = parts[1].trim();
                        // /tmp or /dev/shm with immutable = very suspicious
                        if file.starts_with("/tmp") || file.starts_with("/dev/shm") || file.starts_with("/var/tmp") {
                            send(tx, Finding::new(Severity::Danger, MODULE, "Immutable",
                                &format!("Immutable file in temp directory: {}", file))
                                .with_detail("Rootkits use immutable flag to prevent deletion"));
                        }
                    }
                }
            }
        }
    }
}

fn suspicious_cron_files(tx: &Sender) {
    progress(tx, "Deep scanning cron and persistence...");

    // User crontab
    if let Ok(output) = Command::new("crontab").args(["-l"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !stdout.is_empty() && !stdout.contains("no crontab") {
            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let lower = trimmed.to_lowercase();
                let suspicious_patterns = [
                    "curl", "wget", "base64", "/dev/tcp", "nc ", "ncat",
                    "python -c", "python3 -c", "bash -i", "chmod 777",
                    "/tmp/", "/dev/shm/", ">/dev/null 2>&1 &",
                ];

                for pat in &suspicious_patterns {
                    if lower.contains(pat) {
                        send(tx, Finding::new(Severity::Warning, MODULE, "Cron",
                            &format!("Suspicious cron entry: {}", truncate(trimmed, 80)))
                            .with_detail(trimmed));
                        break;
                    }
                }
            }
        }
    }

    // Shell rc files
    let home = std::env::var("HOME").unwrap_or_default();
    let configs = [".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile"];

    for config in &configs {
        let path = format!("{}/{}", home, config);
        if let Ok(content) = fs::read_to_string(&path) {
            for (i, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let lower = trimmed.to_lowercase();

                let danger_patterns = [
                    "alias sudo=", "alias su=", "/dev/tcp/", "/dev/udp/",
                    "export HISTSIZE=0", "unset HISTFILE", "keylogger",
                    "nc -l", "ncat -l", "curl.*|.*bash", "wget.*|.*sh",
                ];

                for pat in &danger_patterns {
                    if lower.contains(pat) {
                        send(tx, Finding::new(Severity::Danger, MODULE, "Shell Inject",
                            &format!("Dangerous line in {}: line {}", config, i + 1))
                            .with_detail(trimmed));
                        break;
                    }
                }
            }
        }
    }

    // ld.so.preload
    if let Ok(content) = fs::read_to_string("/etc/ld.so.preload") {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            send(tx, Finding::new(Severity::Danger, MODULE, "LD Preload",
                "ld.so.preload has entries — global library injection")
                .with_detail(&format!("Content: {}", trimmed)));
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max]) } else { s.to_string() }
}

pub fn scan(is_root: bool, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    suid_sgid_scan(&tx);
    package_integrity(&tx, is_root);
    devshm_check(&tx);
    world_writable_check(&tx);
    immutable_check(&tx);
    suspicious_cron_files(&tx);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
