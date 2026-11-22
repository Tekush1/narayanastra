use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const MODULE: &str = "OFFLINE";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn target(root: &str, path: &str) -> PathBuf {
    Path::new(root).join(path.trim_start_matches('/'))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  1. KERNEL MODULE SCAN — .ko files on disk
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn kernel_module_scan(tx: &Sender, root: &str) {
    progress(tx, "Scanning kernel modules on disk for rootkit patterns...");

    let modules_dir = target(root, "/lib/modules");
    if !modules_dir.exists() {
        send(tx, Finding::new(Severity::Info, MODULE, "Kernel Modules",
            "No /lib/modules found on target"));
        return;
    }

    let rootkit_ko_names = [
        "diamorphine", "reptile", "bdvl", "jynx", "suterusu", "knark",
        "adore", "enyelkm", "azazel", "brootus", "nurupo", "kovid",
        "beurk", "vlany", "libprocesshider", "khugepagefs",
    ];

    // Hooking signatures found in rootkit kernel modules
    let hook_signatures: &[&[u8]] = &[
        b"sys_call_table",
        b"kallsyms_lookup_name",
        b"register_kretprobe",
        b"__x64_sys_getdents",
        b"__x64_sys_kill",
        b"tcp4_seq_show",
        b"filldir",
        b"orig_",
        b"hook_",
        b"rootkit",
        b"hide_pid",
        b"hide_port",
        b"invisible",
    ];

    let mut suspicious_modules = Vec::new();
    let mut total_scanned = 0u32;

    // Walk all .ko and .ko.xz/.ko.zst files
    if let Ok(output) = Command::new("find")
        .args([modules_dir.to_str().unwrap_or(""), "-name", "*.ko", "-o", "-name", "*.ko.xz", "-o", "-name", "*.ko.zst"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let path = line.trim();
            if path.is_empty() { continue; }
            total_scanned += 1;

            let filename = Path::new(path).file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            // Check known rootkit names
            for rk in &rootkit_ko_names {
                if filename.contains(rk) {
                    send(tx, Finding::new(Severity::Danger, MODULE, "Rootkit Module",
                        &format!("Known rootkit kernel module on disk: {}", path)));
                    suspicious_modules.push(path.to_string());
                }
            }

            // For uncompressed .ko files, scan binary content for hook patterns
            if path.ends_with(".ko") {
                if let Ok(data) = fs::read(path) {
                    let mut hook_count = 0;
                    for sig in hook_signatures {
                        if data.windows(sig.len()).any(|w| w == *sig) {
                            hook_count += 1;
                        }
                    }
                    // 3+ hooking patterns in one module = suspicious
                    if hook_count >= 3 {
                        if !suspicious_modules.contains(&path.to_string()) {
                            send(tx, Finding::new(Severity::Warning, MODULE, "Suspicious Module",
                                &format!("Kernel module has {} hooking patterns: {}", hook_count, path))
                                .with_detail("Contains sys_call_table/hook/hide references — possible rootkit"));
                            suspicious_modules.push(path.to_string());
                        }
                    }
                }
            }
        }
    }

    if suspicious_modules.is_empty() {
        send(tx, Finding::new(Severity::Safe, MODULE, "Kernel Modules",
            &format!("{} kernel modules scanned — no rootkit signatures found", total_scanned)));
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  2. BINARY INTEGRITY — dpkg on target's own DB
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn binary_integrity(tx: &Sender, root: &str) {
    progress(tx, "Verifying binary integrity using target's package database...");

    // Use dpkg with --root to query target disk's own package DB
    let mut child = match Command::new("dpkg")
        .args(["--root", root, "--verify"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn() {
        Ok(c) => c,
        Err(_) => {
            send(tx, Finding::new(Severity::Info, MODULE, "Pkg Integrity",
                "dpkg not available — skipping package integrity check"));
            return;
        }
    };

    let timeout = std::time::Duration::from_secs(60);
    let start_time = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if start_time.elapsed() > timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    send(tx, Finding::new(Severity::Info, MODULE, "Pkg Integrity",
                        "dpkg --verify timed out (>60s) — large system, skipping"));
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

    let mut tampered = Vec::new();
    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }
        // "5" = MD5 checksum mismatch
        if trimmed.contains("5") && trimmed.len() > 10 {
            let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let file_path = parts[1].trim();
                if file_path.starts_with("/etc/") { continue; }
                if file_path.starts_with("/usr/bin/") || file_path.starts_with("/usr/sbin/")
                    || file_path.starts_with("/bin/") || file_path.starts_with("/sbin/")
                    || file_path.contains(".so") {
                    tampered.push(file_path.to_string());
                }
            }
        }
    }

    if tampered.is_empty() {
        send(tx, Finding::new(Severity::Safe, MODULE, "Binary Integrity",
            "All system binaries match package checksums on target disk"));
    } else {
        for path in &tampered {
            send(tx, Finding::new(Severity::Danger, MODULE, "Tampered Binary",
                &format!("Binary doesn't match package checksum: {}", path))
                .with_detail("Offline verification — rootkit cannot hide this"));
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  3. PERSISTENCE SCAN — cron, PAM, systemd, rc
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn persistence_scan(tx: &Sender, root: &str) {
    progress(tx, "Scanning persistence mechanisms on target disk...");

    // ld.so.preload
    let preload = target(root, "/etc/ld.so.preload");
    if let Ok(content) = fs::read_to_string(&preload) {
        let trimmed = content.trim();
        if !trimmed.is_empty() {
            send(tx, Finding::new(Severity::Danger, MODULE, "LD Preload",
                "ld.so.preload has entries on target disk — global library injection")
                .with_detail(&format!("Content: {}", trimmed)));
        }
    }

    // Cron dirs
    let cron_dirs = ["etc/cron.d", "etc/cron.daily", "etc/cron.hourly",
        "etc/cron.weekly", "etc/cron.monthly", "var/spool/cron/crontabs"];
    let bad_patterns = [" curl ", " wget ", " ncat ", "/dev/tcp",
        "python -c", "python3 -c", "bash -i", "chmod 777", "/dev/shm/"];

    for dir in &cron_dirs {
        let cron_path = target(root, dir);
        if let Ok(entries) = fs::read_dir(&cron_path) {
            for entry in entries.flatten() {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    for (i, line) in content.lines().enumerate() {
                        let lower = line.to_lowercase();
                        if line.starts_with('#') { continue; }
                        for pat in &bad_patterns {
                            if lower.contains(pat) {
                                send(tx, Finding::new(Severity::Warning, MODULE, "Cron Persistence",
                                    &format!("Suspicious cron entry in {}/{}: line {}",
                                        dir, entry.file_name().to_string_lossy(), i + 1))
                                    .with_detail(line.trim()));
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Suspicious systemd services
    // Suspicious systemd services — only check user-created ones in etc/systemd/system
    let sd_path = target(root, "etc/systemd/system");
    if let Ok(entries) = fs::read_dir(&sd_path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".service") { continue; }
            // Skip symlinks (enabled services) — only check actual unit files
            if entry.path().is_symlink() { continue; }
            if let Ok(content) = fs::read_to_string(entry.path()) {
                let lower = content.to_lowercase();
                let service_bad = ["/dev/tcp", "bash -i", "python -c", "python3 -c",
                    " ncat ", "chmod 777", "/dev/shm/"];
                for pat in &service_bad {
                    if lower.contains(pat) {
                        send(tx, Finding::new(Severity::Warning, MODULE, "Systemd Persistence",
                            &format!("Suspicious user systemd service: {}", name))
                            .with_detail(&format!("Contains: {}", pat)));
                        break;
                    }
                }
            }
        }
    }

    // PAM backdoor check
    // Skip standard GDM configs — gdm-autologin and gdm-launch-environment
    // legitimately use pam_permit.so for display manager login
    let pam_dir = target(root, "/etc/pam.d");
    if pam_dir.exists() {
        let gdm_safe = ["gdm-autologin", "gdm-launch-environment", "gdm-fingerprint",
            "gdm-smartcard", "lightdm-autologin", "sddm-autologin"];
        if let Ok(entries) = fs::read_dir(&pam_dir) {
            for entry in entries.flatten() {
                let fname = entry.file_name().to_string_lossy().to_string();
                if gdm_safe.iter().any(|g| fname == *g) { continue; }
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    let has_deny = content.lines().any(|l| l.contains("pam_deny.so"));
                    let has_unix = content.lines().any(|l| l.contains("pam_unix.so"));
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') { continue; }
                        if trimmed.contains("pam_permit.so") {
                            if trimmed.contains("sufficient") || (!has_deny && !has_unix) {
                                send(tx, Finding::new(Severity::Danger, MODULE, "PAM Backdoor",
                                    &format!("PAM backdoor in {}: pam_permit.so allows any login", fname))
                                    .with_detail(trimmed));
                            }
                        }
                    }
                }
            }
        }
    }

    // SSH authorized_keys across all users
    let home_base = target(root, "/home");
    let mut homes: Vec<PathBuf> = Vec::new();
    homes.push(target(root, "/root"));
    if let Ok(entries) = fs::read_dir(&home_base) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                homes.push(entry.path());
            }
        }
    }

    for home in &homes {
        let ak_path = home.join(".ssh/authorized_keys");
        if let Ok(content) = fs::read_to_string(&ak_path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
                if trimmed.contains("command=") || trimmed.contains("tunnel") {
                    send(tx, Finding::new(Severity::Warning, MODULE, "SSH Key",
                        &format!("Forced command SSH key in {}", ak_path.display()))
                        .with_detail(trimmed));
                }
            }
        }

        // Shell history → /dev/null symlink
        for hist in &[".bash_history", ".zsh_history"] {
            let hist_path = home.join(hist);
            if hist_path.is_symlink() {
                if let Ok(link_target) = fs::read_link(&hist_path) {
                    if link_target.to_string_lossy().contains("/dev/null") {
                        send(tx, Finding::new(Severity::Warning, MODULE, "History Wiped",
                            &format!("{} is symlink to /dev/null", hist_path.display())));
                    }
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  4. INITRAMFS SCAN — unpack and check
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn initramfs_scan(tx: &Sender, root: &str) {
    progress(tx, "Scanning initramfs for backdoors...");

    let boot_dir = target(root, "/boot");
    if !boot_dir.exists() {
        send(tx, Finding::new(Severity::Info, MODULE, "Initramfs",
            "No /boot found on target"));
        return;
    }

    // Find initramfs/initrd files
    let mut initrd_files = Vec::new();
    if let Ok(entries) = fs::read_dir(&boot_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("initrd") || name.starts_with("initramfs") {
                initrd_files.push(entry.path());
            }
        }
    }

    if initrd_files.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "Initramfs",
            "No initramfs/initrd found in /boot"));
        return;
    }

    for initrd in &initrd_files {
        let tmp_dir = format!("/tmp/narayanastra_initrd_{}", std::process::id());
        let _ = fs::create_dir_all(&tmp_dir);

        // Try unmkinitramfs first (Debian/Ubuntu), fall back to cpio
        let extracted = Command::new("unmkinitramfs")
            .args([initrd.to_str().unwrap_or(""), &tmp_dir])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if !extracted {
            // Try lsinitrd for listing only (RHEL/Fedora)
            if let Ok(output) = Command::new("lsinitrd").arg(initrd).output() {
                let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
                for rk in &["diamorphine", "reptile", "bdvl", "rootkit", "backdoor"] {
                    if stdout.contains(rk) {
                        send(tx, Finding::new(Severity::Danger, MODULE, "Initramfs Rootkit",
                            &format!("Rootkit reference '{}' in {}", rk, initrd.display())));
                    }
                }
            }
            let _ = fs::remove_dir_all(&tmp_dir);
            continue;
        }

        // Scan extracted contents
        if let Ok(output) = Command::new("find")
            .args([&tmp_dir, "-type", "f"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let path = line.trim();
                if path.is_empty() { continue; }

                let filename = Path::new(path).file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_lowercase();

                // Known rootkit modules inside initramfs
                let rootkit_names = ["diamorphine", "reptile", "bdvl", "jynx",
                    "suterusu", "kovid", "beurk"];
                for rk in &rootkit_names {
                    if filename.contains(rk) {
                        send(tx, Finding::new(Severity::Danger, MODULE, "Initramfs Rootkit",
                            &format!("Rootkit module '{}' embedded in initramfs: {}",
                                rk, initrd.display()))
                            .with_detail(&format!("File: {}", path)));
                    }
                }

                // .ko files in initramfs — scan for hooks
                if path.ends_with(".ko") {
                    if let Ok(data) = fs::read(path) {
                        let hook_sigs: &[&[u8]] = &[
                            b"sys_call_table", b"hide_pid", b"hide_port", b"rootkit",
                        ];
                        let mut hits = 0;
                        for sig in hook_sigs {
                            if data.windows(sig.len()).any(|w| w == *sig) {
                                hits += 1;
                            }
                        }
                        if hits >= 2 {
                            send(tx, Finding::new(Severity::Warning, MODULE, "Initramfs Hook",
                                &format!("Kernel module in initramfs has {} hook signatures: {}",
                                    hits, filename))
                                .with_detail(&format!("Inside: {}", initrd.display())));
                        }
                    }
                }

                // Scripts with suspicious content — only .sh files
                if path.ends_with(".sh") {
                    if let Ok(content) = fs::read_to_string(path) {
                        let lower = content.to_lowercase();
                        let suspicious = ["/dev/tcp", "backdoor", "rootkit",
                            "reverse_shell", "bind_shell", "meterpreter"];
                        for pat in &suspicious {
                            if lower.contains(pat) {
                                send(tx, Finding::new(Severity::Warning, MODULE, "Initramfs Script",
                                    &format!("Suspicious pattern '{}' in initramfs script: {}",
                                        pat, filename))
                                    .with_detail(&format!("Inside: {}", initrd.display())));
                                break;
                            }
                        }
                    }
                }
            }
        }

        let _ = fs::remove_dir_all(&tmp_dir);
    }

    send(tx, Finding::new(Severity::Info, MODULE, "Initramfs",
        &format!("{} initramfs image(s) scanned", initrd_files.len())));
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  5. BOOTLOADER SCAN — GRUB integrity
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn bootloader_scan(tx: &Sender, root: &str) {
    progress(tx, "Checking bootloader integrity...");

    // GRUB config
    let grub_cfg = target(root, "/boot/grub/grub.cfg");
    let grub_cfg2 = target(root, "/boot/grub2/grub.cfg");

    let grub_path = if grub_cfg.exists() { Some(grub_cfg) }
        else if grub_cfg2.exists() { Some(grub_cfg2) }
        else { None };

    if let Some(ref path) = grub_path {
        if let Ok(content) = fs::read_to_string(path) {
            let lower = content.to_lowercase();

            // Check for suspicious kernel parameters
            let suspicious_params = ["init=/bin/sh", "init=/bin/bash", "single",
                "rd.break", "rdinit=", "debug_shell"];
            for param in &suspicious_params {
                if lower.contains(&param.to_lowercase()) {
                    send(tx, Finding::new(Severity::Warning, MODULE, "GRUB Config",
                        &format!("Suspicious boot parameter in grub.cfg: {}", param))
                        .with_detail("Could be used for persistent root shell on boot"));
                }
            }

            // Custom entries that load unknown modules
            if lower.contains("insmod") {
                for line in content.lines() {
                    let trimmed = line.trim().to_lowercase();
                    if trimmed.starts_with("insmod") {
                        let known_grub_modules = ["ext2", "ext4", "xfs", "btrfs", "fat",
                            "ntfs", "part_gpt", "part_msdos", "normal", "linux",
                            "loopback", "gzio", "lvm", "raid", "search",
                            "configfile", "terminal", "serial", "video",
                            "gfxterm", "gfxmenu", "png", "font", "echo",
                            "ls", "cat", "test", "true", "sleep", "reboot",
                            "halt", "iso9660", "udf", "all_video", "boot",
                            "chain", "cryptodisk", "luks", "gcry_rijndael",
                            "gcry_sha256", "mdraid09", "mdraid1x", "diskfilter",
                            "loadenv", "keystatus", "regexp", "probe",
                            "password_pbkdf2", "gcry_sha512", "lzopio",
                            "search_fs_uuid", "search_fs_file", "search_label",
                            "biosdisk", "multiboot", "play", "trig",
                            "lspci", "usb", "uhci", "ohci", "ehci",
                            "usbms", "xhci"];
                        let module_name = trimmed.replace("insmod", "").trim().to_string();
                        if !module_name.is_empty() && !known_grub_modules.iter().any(|m| module_name.contains(m)) {
                            send(tx, Finding::new(Severity::Warning, MODULE, "GRUB Module",
                                &format!("Unknown GRUB module loaded: {}", module_name)));
                        }
                    }
                }
            }
        }
    }

    // Check GRUB binary itself
    let grub_bins = [
        target(root, "/boot/grub/i386-pc/core.img"),
        target(root, "/boot/grub/x86_64-efi/grubx64.efi"),
        target(root, "/boot/efi/EFI/debian/grubx64.efi"),
        target(root, "/boot/efi/EFI/ubuntu/grubx64.efi"),
        target(root, "/boot/efi/EFI/kali/grubx64.efi"),
    ];

    for bin in &grub_bins {
        if bin.exists() {
            if let Ok(meta) = bin.metadata() {
                // GRUB EFI binary should be owned by root
                if meta.uid() != 0 {
                    send(tx, Finding::new(Severity::Danger, MODULE, "Bootloader",
                        &format!("GRUB binary not owned by root: {}", bin.display()))
                        .with_detail(&format!("Owner: uid={}", meta.uid())));
                }
                // Check if writable by others
                if meta.permissions().mode() & 0o022 != 0 {
                    send(tx, Finding::new(Severity::Danger, MODULE, "Bootloader",
                        &format!("GRUB binary is world/group writable: {}", bin.display())));
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  6. HIDDEN FILES — raw filesystem scan
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn hidden_files_scan(tx: &Sender, root: &str) {
    progress(tx, "Scanning for hidden malware on disk (rootkit can't hide from offline scan)...");

    let scan_dirs = ["tmp", "dev/shm", "var/tmp", "run"];
    for dir in &scan_dirs {
        let scan_path = target(root, dir);
        if !scan_path.exists() { continue; }

        if let Ok(entries) = fs::read_dir(&scan_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                // ELF binaries in temp dirs
                if path.is_file() {
                    if let Ok(data) = fs::read(&path) {
                        if data.len() >= 4 && &data[..4] == b"\x7fELF" {
                            send(tx, Finding::new(Severity::Danger, MODULE, "Hidden Binary",
                                &format!("ELF binary in {}: {}", dir, name))
                                .with_detail(&format!("Size: {} bytes — invisible to live rootkit-hidden scan", data.len())));
                        }
                        if data.len() >= 2 && &data[..2] == b"MZ" {
                            send(tx, Finding::new(Severity::Danger, MODULE, "Hidden PE",
                                &format!("PE executable in {}: {}", dir, name)));
                        }
                    }
                }

                // Hidden dirs with executables
                if name.starts_with('.') && name != "." && name != ".." && path.is_dir() {
                    if let Ok(sub_entries) = fs::read_dir(&path) {
                        for sub in sub_entries.flatten() {
                            if sub.path().is_file() {
                                if let Ok(data) = fs::read(sub.path()) {
                                    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
                                        send(tx, Finding::new(Severity::Danger, MODULE, "Hidden Dir Binary",
                                            &format!("ELF in hidden dir: {}/{}/{}",
                                                dir, name, sub.file_name().to_string_lossy()))
                                            .with_detail("Offline scan — rootkit cannot hide this file"));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // SUID binaries in unusual locations
    let suid_scan_dirs = ["tmp", "var/tmp", "dev/shm", "home"];
    for dir in &suid_scan_dirs {
        let scan_path = target(root, dir);
        if !scan_path.exists() { continue; }

        if let Ok(output) = Command::new("find")
            .args([scan_path.to_str().unwrap_or(""), "-perm", "-4000", "-type", "f"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let path = line.trim();
                if !path.is_empty() {
                    send(tx, Finding::new(Severity::Danger, MODULE, "Hidden SUID",
                        &format!("SUID binary in suspicious location: {}", path))
                        .with_detail("Could be privilege escalation backdoor"));
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  7. LOG EVIDENCE — check for wiping
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn log_evidence_scan(tx: &Sender, root: &str) {
    progress(tx, "Checking logs for evidence of tampering...");

    let critical_logs = [
        "var/log/auth.log", "var/log/syslog", "var/log/kern.log",
        "var/log/messages", "var/log/secure", "var/log/audit/audit.log",
    ];

    for log in &critical_logs {
        let log_path = target(root, log);
        if !log_path.exists() { continue; }

        if let Ok(meta) = log_path.metadata() {
            // Zero-byte critical log
            if meta.len() == 0 {
                send(tx, Finding::new(Severity::Danger, MODULE, "Log Wiped",
                    &format!("Critical log file is empty: {}", log))
                    .with_detail("Log was likely wiped by attacker"));
            }
            // Wrong owner
            if meta.uid() != 0 && meta.uid() != 104 { // 104 = syslog
                send(tx, Finding::new(Severity::Warning, MODULE, "Log Owner",
                    &format!("Log file has unusual owner (uid={}): {}", meta.uid(), log)));
            }
        }
    }

    // Check if wtmp/btmp were truncated
    let wtmp = target(root, "var/log/wtmp");
    if let Ok(meta) = wtmp.metadata() {
        if meta.len() == 0 {
            send(tx, Finding::new(Severity::Danger, MODULE, "Login Log Wiped",
                "wtmp is empty — login records were wiped"));
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  PUBLIC ENTRY POINT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub fn scan(root: &str, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    // Verify target exists and looks like a Linux root
    let etc = target(root, "/etc");
    let usr = target(root, "/usr");
    if !etc.exists() || !usr.exists() {
        send(&tx, Finding::new(Severity::Danger, MODULE, "Target",
            &format!("Target '{}' doesn't look like a Linux root filesystem", root))
            .with_detail("Missing /etc or /usr — make sure the disk is mounted correctly"));
        let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
        return;
    }

    send(&tx, Finding::new(Severity::Info, MODULE, "Target",
        &format!("Scanning offline target: {}", root)));

    kernel_module_scan(&tx, root);
    binary_integrity(&tx, root);
    persistence_scan(&tx, root);
    initramfs_scan(&tx, root);
    bootloader_scan(&tx, root);
    hidden_files_scan(&tx, root);
    log_evidence_scan(&tx, root);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
