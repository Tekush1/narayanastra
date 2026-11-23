use crate::config::ScanConfig;
use crate::pkg::{self, Ownership};
use crate::procfs;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

const MODULE: &str = "ANTIFOR";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

fn timestomping_check(tx: &Sender) {
    progress(tx, "Checking system binaries for timestamp manipulation...");
    let now = util::now_epoch();
    let mut stomped = 0;
    for dir in ["/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/bin", "/usr/local/sbin"] {
        util::walk(Path::new(dir), 1, true, 500_000, |e| {
            if !e.meta.file_type().is_file() {
                return;
            }
            let (mtime, ctime) = (e.meta.mtime(), e.meta.ctime());
            let path = e.path.to_string_lossy().into_owned();
            if mtime > now + 86400 {
                stomped += 1;
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Timestomp", &format!("Future-dated file: {}", path))
                        .with_detail(&format!("mtime is {}s in the future", mtime - now))
                        .subject(&path)
                        .artifact(&path),
                );
            } else if mtime > 1 && mtime < 946_684_800 && ctime > now - 86400 * 365 {
                // pre-2000 mtime on a file whose inode changed this year (Nix/reproducible
                // builds use mtime 0/1 and are skipped)
                stomped += 1;
                send(
                    tx,
                    Finding::new(Severity::Warning, MODULE, "Timestomp", &format!("Backdated binary (pre-2000 mtime, recent ctime): {}", path))
                        .with_detail(&format!("mtime={} ctime={} — touch -t/-r cannot fake ctime", mtime, ctime))
                        .subject(&path)
                        .artifact(&path),
                );
            }
        });
    }
    if stomped == 0 {
        send(tx, Finding::new(Severity::Safe, MODULE, "Timestamps", "No timestamp anomalies in system binaries").subject("timestamps"));
    }
}

fn hidden_files_check(tx: &Sender) {
    progress(tx, "Scanning for hidden files and directories with executable content...");
    for dir in ["/tmp", "/var/tmp", "/dev/shm", "/usr/lib", "/usr/share", "/usr/local", "/opt", "/var/lib", "/etc", "/lib/modules"] {
        util::walk(Path::new(dir), 2, true, 300_000, |e| {
            let name = e.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let path = e.path.to_string_lossy().into_owned();
            if name == "..." || name == ".. " || name == ". " || name.trim().is_empty() {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Hidden Dir", &format!("Deceptive name '{}' at {}", name.escape_debug(), path))
                        .with_detail("'...', '.. ' and blank names are classic rootkit hiding spots")
                        .subject(&path),
                );
            }
            if name.chars().any(|c| matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}' | '\u{00a0}' | '\u{202e}')) {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Unicode Hide", &format!("Name with invisible/bidi Unicode: {}", path.escape_debug()))
                        .subject(&path),
                );
            }
            if !name.starts_with('.') || !e.meta.file_type().is_file() {
                return;
            }
            let head = util::read_head(&e.path, 1024).unwrap_or_default();
            if util::is_elf(&head) || util::is_pe(&head) {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Hidden Binary", &format!("Hidden executable: {}", path))
                        .with_detail(&format!("Size: {} bytes", e.meta.len()))
                        .subject(&path)
                        .artifact(&path),
                );
            } else if head.starts_with(b"#!") {
                let script = String::from_utf8_lossy(&head).to_lowercase();
                if ["curl ", "wget ", "/dev/tcp", "base64 -d", "nc -e", "eval "].iter().any(|p| script.contains(p)) {
                    send(
                        tx,
                        Finding::new(Severity::Warning, MODULE, "Hidden Script", &format!("Hidden script with download/exec logic: {}", path))
                            .subject(&path)
                            .artifact(&path),
                    );
                }
            }
        });
    }
    // home dirs: only flag ELF binaries one level inside hidden dirs (no name whitelist)
    let root = Root::live();
    for (_, home) in util::interesting_homes(&root) {
        for sub in root.read_dir(&home) {
            if !sub.starts_with('.') {
                continue;
            }
            let dir = format!("{}/{}", home, sub);
            if sub.contains("..") || sub.trim_start_matches('.').trim().is_empty() {
                send(
                    tx,
                    Finding::new(Severity::Warning, MODULE, "Suspicious Dotdir", &format!("Deceptive hidden directory name: '{}'", dir.escape_debug()))
                        .subject(&dir),
                );
            }
            util::walk(Path::new(&dir), 0, true, 5000, |e| {
                if e.meta.file_type().is_file() && e.meta.mode() & 0o111 != 0 {
                    if let Some(h) = util::read_head(&e.path, 4) {
                        if util::is_elf(&h) {
                            let p = e.path.to_string_lossy().into_owned();
                            send(
                                tx,
                                Finding::new(Severity::Warning, MODULE, "Hidden Executable", &format!("ELF binary directly inside hidden home dir: {}", p))
                                    .subject(&p)
                                    .artifact(&p),
                            );
                        }
                    }
                }
            });
        }
    }
}

fn log_tampering_check(tx: &Sender) {
    progress(tx, "Checking log files for wiping and wrong ownership...");
    let root = Root::live();
    let mut ok_uids =
        util::uids_of(&root, &["root", "syslog", "_apt", "systemd-journal", "messagebus", "gdm", "lightdm", "Debian-gdm", "sddm", "unattended-upgrades"]);
    ok_uids.push(0);
    let ok_gids = util::gids_of(&root, &["adm", "systemd-journal", "utmp", "syslog", "root"]);
    for log in ["/var/log/auth.log", "/var/log/syslog", "/var/log/kern.log", "/var/log/messages", "/var/log/secure"] {
        if let Some(meta) = root.lstat(log) {
            if meta.file_type().is_symlink() {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Wiped Log", &format!("{} is a symlink to {}", log, root.readlink(log).unwrap_or_default()))
                        .subject(&format!("symlink:{}", log)),
                );
            }
        }
    }
    for name in root.read_dir("/var/log") {
        let path = format!("/var/log/{}", name);
        if let Some(meta) = root.lstat(&path) {
            if meta.is_file()
                && (name.ends_with(".log") || name == "wtmp" || name == "btmp" || name == "lastlog")
                && !ok_uids.contains(&meta.uid())
                && !ok_gids.contains(&meta.gid())
                && meta.uid() < 1000
            {
                send(
                    tx,
                    Finding::new(Severity::Warning, MODULE, "Log Owner", &format!("{} is owned by uid {} gid {}", path, meta.uid(), meta.gid())).subject(&path),
                );
            }
        }
    }
}

/// pam_unix ownership + PAM config backdoor patterns, on every distro and architecture.
pub fn pam_checks(root: &Root, tx: &Sender, module: &str) {
    let mut lib_dirs: Vec<String> = vec!["/lib/security".into(), "/lib64/security".into(), "/usr/lib/security".into(), "/usr/lib64/security".into()];
    for base in ["/lib", "/usr/lib"] {
        for d in root.read_dir(base) {
            if d.ends_with("-linux-gnu") || d.ends_with("-linux-musl") || d.ends_with("-linux-gnueabihf") {
                lib_dirs.push(format!("{}/{}/security", base, d));
            }
        }
    }
    let mut seen_real = std::collections::HashSet::new();
    for dir in &lib_dirs {
        for so in root.read_dir(dir) {
            if !so.ends_with(".so") {
                continue;
            }
            let path = format!("{}/{}", dir, so);
            let real = root.resolve(&path).map(|p| root.inner(&p)).unwrap_or(path.clone());
            if !seen_real.insert(real.clone()) {
                continue;
            }
            if pkg::owner(root, &path) == Ownership::NotOwned && pkg::owner(root, &real) == Ownership::NotOwned {
                send(
                    tx,
                    Finding::new(Severity::Danger, module, "PAM Backdoor", &format!("PAM module not owned by any package: {}", root.display(&real)))
                        .with_detail("Unpackaged PAM modules are how pam_backdoor / skeleton-key implants log or bypass passwords")
                        .subject(&format!("pamlib:{}", real))
                        .artifact(&root.display(&real)),
                );
            }
        }
    }
    let safe_autologin = ["gdm-autologin", "gdm-launch-environment", "lightdm-autologin", "sddm-autologin", "gdm-fingerprint", "gdm-smartcard"];
    for name in root.read_dir("/etc/pam.d") {
        if safe_autologin.contains(&name.as_str()) {
            continue;
        }
        let path = format!("/etc/pam.d/{}", name);
        let content = match root.read_string(&path, 1024 * 1024) {
            Some(c) => c,
            None => continue,
        };
        let active: Vec<&str> = content.lines().map(|l| l.trim()).filter(|l| !l.starts_with('#') && !l.is_empty()).collect();
        let has_deny = active.iter().any(|l| l.contains("pam_deny.so"));
        let has_auth_stack = active.iter().any(|l| {
            l.starts_with("auth") && (l.contains("pam_unix.so") || l.contains("pam_sss.so") || l.contains("pam_ldap") || l.contains("pam_krb5"))
                || l.starts_with("@include")
                || l.contains("include")
                || l.contains("substack")
        });
        for l in &active {
            let is_auth = l.starts_with("auth") || l.starts_with("-auth");
            if is_auth && l.contains("pam_permit.so") && (l.contains("sufficient") || l.contains("success=done")) {
                send(
                    tx,
                    Finding::new(Severity::Danger, module, "PAM Backdoor", &format!("pam_permit.so as SUFFICIENT auth in {}", path))
                        .with_detail(&format!("{}\nAny password is accepted", l))
                        .subject(&format!("pamconf:{}:{}", path, l)),
                );
            } else if is_auth && l.contains("pam_permit.so") && !has_deny && !has_auth_stack {
                send(
                    tx,
                    Finding::new(Severity::Danger, module, "PAM Backdoor", &format!("{} authenticates with pam_permit.so and no real auth module", path))
                        .with_detail(l)
                        .subject(&format!("pamconf:{}:{}", path, l)),
                );
            }
            if is_auth && l.contains("pam_exec.so") {
                let script = l.split_whitespace().find(|w| w.starts_with('/')).unwrap_or("");
                let sev = if util::is_temp_path(script) || util::has_hidden_component(script) || l.contains("expose_authtok") {
                    Severity::Danger
                } else {
                    Severity::Warning
                };
                send(
                    tx,
                    Finding::new(sev, module, "PAM Backdoor", &format!("pam_exec in auth stack of {} runs {}", path, script))
                        .with_detail(&format!("{}\nexpose_authtok hands the plaintext password to the script", l))
                        .subject(&format!("pamexec:{}:{}", path, script)),
                );
            }
        }
    }
}

fn suspicious_environment(tx: &Sender) {
    progress(tx, "Checking process environments for startup hooks...");
    for pid in util::proc_pids() {
        let data = match util::read_proc_bytes(format!("/proc/{}/environ", pid)) {
            Some(d) => d,
            None => continue,
        };
        for var in data.split(|&b| b == 0) {
            let var = String::from_utf8_lossy(var);
            for key in ["BASH_ENV=", "ENV=", "PROMPT_COMMAND="] {
                if let Some(v) = var.strip_prefix(key) {
                    let lower = v.to_lowercase();
                    let bad = util::is_temp_path(v) || ["/dev/tcp", "curl ", "wget ", "nc ", "base64"].iter().any(|p| lower.contains(p));
                    if bad {
                        send(
                            tx,
                            Finding::new(
                                Severity::Warning,
                                MODULE,
                                "Env Var",
                                &format!("PID {} ({}) has {}{}", pid, procfs::comm(pid), key, util::truncate(v, 80)),
                            )
                            .subject(&format!("env:{}:{}", pid, key)),
                        );
                    }
                }
            }
        }
    }
}

fn rootkit_artifacts(tx: &Sender) {
    progress(tx, "Checking for known rootkit artifacts (signatures)...");
    let files = [
        "/dev/.reptile",
        "/reptile",
        "/usr/lib/jynx2",
        "/var/tmp/.azazel",
        "/dev/.hid",
        "/dev/.sd0",
        "/dev/.sd1",
        "/usr/lib/.hid",
        "/usr/share/.hid",
        "/tmp/.font-unix/.x",
        "/tmp/.ICE-unix/.x",
        "/tmp/.X25-unix/.x",
        "/usr/bin/.sshd",
    ];
    for path in files {
        if Root::live().exists(path) {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Rootkit File", &format!("Known rootkit/implant artifact present: {}", path))
                    .subject(path)
                    .artifact(path),
            );
        }
    }
}

pub fn scan(_cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    timestomping_check(&tx);
    hidden_files_check(&tx);
    log_tampering_check(&tx);
    progress(&tx, "Checking PAM modules and configuration...");
    pam_checks(&Root::live(), &tx, MODULE);
    suspicious_environment(&tx);
    rootkit_artifacts(&tx);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
