use crate::config::ScanConfig;
use crate::pkg::{self, Ownership};
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

const MODULE: &str = "FILES";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

/// SUID/SGID scan. Files are judged by package ownership rather than by name, so a
/// backdoor cannot hide behind a familiar basename; temp/home locations are always flagged.
fn suid_sgid_scan(cfg: &ScanConfig, tx: &Sender) {
    progress(tx, "Scanning for SUID/SGID binaries (package ownership based)...");
    let root = Root::live();
    let depth = if cfg.full { 32 } else { 4 };
    let dirs = [
        "/usr/bin",
        "/usr/sbin",
        "/usr/local",
        "/usr/lib",
        "/usr/lib64",
        "/usr/libexec",
        "/opt",
        "/srv",
        "/tmp",
        "/var/tmp",
        "/dev/shm",
        "/home",
        "/root",
        "/var/www",
    ];
    let mut total = 0usize;
    let mut bad = 0usize;
    for dir in dirs {
        if !Path::new(dir).exists() {
            continue;
        }
        util::walk(Path::new(dir), depth, true, 2_000_000, |e| {
            if !e.meta.file_type().is_file() {
                return;
            }
            let mode = e.meta.mode();
            let (suid, sgid) = (mode & 0o4000 != 0, mode & 0o2000 != 0);
            if !(suid || sgid) {
                return;
            }
            total += 1;
            let path = e.path.to_string_lossy().into_owned();
            let flag = if suid { "SUID" } else { "SGID" };
            // container image layers keep SUID bits on their own (rootless podman/docker)
            if path.contains("/.local/share/containers/") || path.contains("/.local/share/docker/") || path.contains("/overlay2/") {
                return;
            }
            let in_bad_place = util::is_temp_path(&path)
                || path.starts_with("/home/")
                || path.starts_with("/root/")
                || path.starts_with("/var/www/")
                || util::has_hidden_component(&path);
            if in_bad_place && e.meta.uid() != 0 {
                // a user-owned SUID file only grants that user's own rights
                send(tx, Finding::new(Severity::Info, MODULE, flag, &format!("User-owned {} file in user/temp location: {}", flag, path)).subject(&path));
                return;
            }
            if in_bad_place {
                bad += 1;
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, flag, &format!("{} binary in a user/temp location: {}", flag, path))
                        .with_detail(&format!("Mode: {:o}, owner uid={} — classic privilege-escalation backdoor", mode, e.meta.uid()))
                        .subject(&path)
                        .artifact(&path),
                );
                return;
            }
            match pkg::owner(&root, &path) {
                Ownership::Owned => {}
                Ownership::NotOwned => {
                    bad += 1;
                    send(
                        tx,
                        Finding::new(
                            if suid && e.meta.uid() == 0 { Severity::Warning } else { Severity::Info },
                            MODULE,
                            flag,
                            &format!("{} binary not owned by any package: {}", flag, path),
                        )
                        .with_detail(&format!("Mode: {:o}, owner uid={}", mode, e.meta.uid()))
                        .subject(&path)
                        .artifact(&path),
                    );
                }
                Ownership::Unknown => {}
            }
        });
    }
    if bad == 0 {
        send(
            tx,
            Finding::new(Severity::Safe, MODULE, "SUID/SGID", &format!("{} SUID/SGID files, all package-owned and in system paths", total)).subject("suid"),
        );
    } else {
        send(tx, Finding::new(Severity::Info, MODULE, "SUID/SGID", &format!("{} SUID/SGID files, {} need review", total, bad)).subject("suid"));
    }
}

fn package_integrity(cfg: &ScanConfig, tx: &Sender) {
    let root = Root::live();
    if let Some(db) = &cfg.hashdb {
        progress(tx, "Verifying binaries against trusted hashdb...");
        match pkg::verify_hashdb(&root, db) {
            Ok(r) => report_verify(tx, r, "hashdb"),
            Err(e) => send(tx, Finding::new(Severity::Warning, MODULE, "Pkg Integrity", &e).subject("hashdb")),
        }
    }
    if !cfg.is_root {
        progress(tx, "Package integrity limited (some files unreadable without root)...");
    }
    let pm = pkg::pm_of(&root);
    progress(
        tx,
        &format!(
            "Verifying {} files against {} checksums ({})...",
            if cfg.full { "all packaged" } else { "critical" },
            pm,
            if pm == pkg::Pm::Dpkg { "native md5" } else { "package manager" }
        ),
    );
    let budget = if cfg.full { Duration::from_secs(600) } else { Duration::from_secs(60) };
    let r = pkg::verify(&root, cfg.full, budget);
    report_verify(tx, r, &pm.to_string());
}

pub fn report_verify(tx: &Sender, r: pkg::VerifyResult, source: &str) {
    report_verify_as(tx, r, source, MODULE)
}

pub fn report_verify_as(tx: &Sender, r: pkg::VerifyResult, source: &str, module: &str) {
    for (path, why) in &r.tampered {
        // executables and loader-relevant libraries are high-signal; data files
        // (certs, wheels, docs) changed by admins or updates are worth a look, not an alarm
        let head = util::read_head(path, 4).unwrap_or_default();
        let code = pkg::is_critical(path) || util::is_elf(&head) || path.contains("/bin/") || path.contains("/sbin/");
        send(
            tx,
            Finding::new(
                if code { Severity::Danger } else { Severity::Warning },
                module,
                if code { "Tampered Binary" } else { "Pkg Integrity" },
                &format!("{} differs from its package checksum: {}", if code { "Executable code" } else { "Packaged file" }, path),
            )
            .with_detail(why)
            .subject(path)
            .artifact(path),
        );
    }
    if !r.missing.is_empty() {
        let critical: Vec<&String> = r.missing.iter().filter(|p| pkg::is_critical(p)).collect();
        if !critical.is_empty() {
            send(
                tx,
                Finding::new(Severity::Warning, module, "Pkg Integrity", &format!("{} packaged critical file(s) are missing", critical.len()))
                    .with_detail(&critical.iter().take(20).map(|s| s.as_str()).collect::<Vec<_>>().join("\n"))
                    .subject(&format!("missing:{}", source)),
            );
        }
    }
    if r.timed_out {
        send(
            tx,
            Finding::new(
                Severity::Info,
                module,
                "Pkg Integrity",
                &format!("Verification budget exhausted after {} files — run with --full for a complete pass", r.checked),
            )
            .subject(&format!("timeout:{}", source)),
        );
    }
    if let Some(n) = &r.note {
        send(tx, Finding::new(Severity::Info, module, "Pkg Integrity", n).subject(&format!("note:{}", source)));
    }
    if r.tampered.is_empty() && r.checked > 0 {
        send(
            tx,
            Finding::new(Severity::Safe, module, "Pkg Integrity", &format!("{} files match {} checksums", r.checked, source))
                .subject(&format!("ok:{}", source)),
        );
    }
}

/// Executable content in shared memory / runtime dirs (single owner of this check).
fn devshm_check(tx: &Sender) {
    progress(tx, "Checking /dev/shm and runtime dirs for executables...");
    for dir in ["/dev/shm", "/run/shm", "/dev/mqueue"] {
        util::walk(Path::new(dir), 3, true, 100_000, |e| {
            if !e.meta.file_type().is_file() {
                return;
            }
            let path = e.path.to_string_lossy().into_owned();
            let head = util::read_head(&e.path, 4096).unwrap_or_default();
            let exec_bit = e.meta.permissions().mode() & 0o111 != 0;
            let what = if util::is_elf(&head) {
                Some("ELF binary")
            } else if util::is_pe(&head) {
                Some("PE executable")
            } else if head.starts_with(b"#!") && exec_bit {
                Some("executable script")
            } else if head.windows(16).any(|w| w.iter().all(|&b| b == 0x90)) {
                Some("possible shellcode (NOP sled)")
            } else {
                None
            };
            if let Some(w) = what {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "/dev/shm", &format!("{} in shared memory: {}", w, path))
                        .with_detail(&format!("Size: {} bytes, mode {:o} — tmpfs staging is a common malware pattern", e.meta.len(), e.meta.mode()))
                        .subject(&path)
                        .artifact(&path),
                );
            }
        });
    }
}

fn world_writable_check(cfg: &ScanConfig, tx: &Sender) {
    progress(tx, "Checking for world-writable files/dirs in sensitive locations...");
    let depth = if cfg.full { 16 } else { 2 };
    for dir in ["/etc", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/bin", "/usr/local/sbin", "/boot"] {
        util::walk(Path::new(dir), depth, true, 1_000_000, |e| {
            let ft = e.meta.file_type();
            let mode = e.meta.mode();
            let path = e.path.to_string_lossy().into_owned();
            if ft.is_file() && mode & 0o002 != 0 {
                send(
                    tx,
                    Finding::new(Severity::Warning, MODULE, "World-Writable", &format!("World-writable file: {}", path))
                        .with_detail(&format!("Mode {:o}", mode))
                        .subject(&path),
                );
            } else if ft.is_dir() && mode & 0o002 != 0 && mode & 0o1000 == 0 {
                send(
                    tx,
                    Finding::new(Severity::Warning, MODULE, "World-Writable", &format!("World-writable directory without sticky bit: {}", path))
                        .with_detail(&format!("Mode {:o}", mode))
                        .subject(&path),
                );
            }
        });
    }
}

const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
const FS_IMMUTABLE_FL: libc::c_long = 0x10;
const FS_APPEND_FL: libc::c_long = 0x20;

fn inode_flags(path: &Path) -> Option<libc::c_long> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC).open(path).ok()?;
    let mut flags: libc::c_long = 0;
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS as _, &mut flags) };
    if rc == 0 {
        Some(flags)
    } else {
        None
    }
}

use std::os::unix::fs::OpenOptionsExt;

fn immutable_check(cfg: &ScanConfig, tx: &Sender) {
    progress(tx, "Checking immutable/append-only flags (FS_IOC_GETFLAGS)...");
    let depth = if cfg.full { 8 } else { 2 };
    for dir in ["/tmp", "/var/tmp", "/dev/shm", "/usr/bin", "/usr/sbin", "/etc/cron.d", "/etc/systemd/system", "/root/.ssh", "/etc/ld.so.preload"] {
        let p = Path::new(dir);
        let check = |path: &Path| {
            if let Some(flags) = inode_flags(path) {
                if flags & (FS_IMMUTABLE_FL | FS_APPEND_FL) != 0 {
                    let ps = path.to_string_lossy().into_owned();
                    let temp = util::is_temp_path(&ps);
                    let kind = if flags & FS_IMMUTABLE_FL != 0 { "immutable" } else { "append-only" };
                    send(
                        tx,
                        Finding::new(if temp { Severity::Danger } else { Severity::Warning }, MODULE, "Immutable", &format!("{} file: {}", kind, ps))
                            .with_detail("Rootkits set chattr +i so their files and persistence can't be removed")
                            .subject(&ps)
                            .artifact(&ps),
                    );
                }
            }
        };
        if p.is_file() {
            check(p);
            continue;
        }
        util::walk(p, depth, true, 500_000, |e| {
            if e.meta.file_type().is_file() {
                check(&e.path);
            }
        });
    }
}

pub fn scan(cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    suid_sgid_scan(cfg, &tx);
    package_integrity(cfg, &tx);
    devshm_check(&tx);
    world_writable_check(cfg, &tx);
    immutable_check(cfg, &tx);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
