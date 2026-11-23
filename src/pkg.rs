//! Package-manager awareness: ownership lookups and integrity verification for
//! dpkg, rpm, pacman and apk — live or against an offline root.
//!
//! dpkg is verified natively (we parse info/*.md5sums and hash files ourselves) so a
//! trojaned /usr/bin/dpkg on the live host cannot lie to us. "Unknown" (no package
//! manager) is never treated as "not owned", so hosts without a supported package
//! manager do not produce ownership-based false positives.

use crate::hash;
use crate::util::{self, Root};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pm {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Unknown,
}

impl std::fmt::Display for Pm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Pm::Dpkg => "dpkg",
            Pm::Rpm => "rpm",
            Pm::Pacman => "pacman",
            Pm::Apk => "apk",
            Pm::Unknown => "unknown",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ownership {
    Owned,
    NotOwned,
    Unknown,
}

pub fn detect(root: &Root) -> Pm {
    if root.exists("/var/lib/dpkg/status") {
        Pm::Dpkg
    } else if root.exists("/var/lib/rpm") || root.exists("/usr/lib/sysimage/rpm") {
        Pm::Rpm
    } else if root.exists("/var/lib/pacman/local") {
        Pm::Pacman
    } else if root.exists("/lib/apk/db/installed") {
        Pm::Apk
    } else {
        Pm::Unknown
    }
}

/// usrmerge aliases: dpkg may have registered /bin/su while the file lives at /usr/bin/su.
pub fn aliases(path: &str) -> Vec<String> {
    let mut v = vec![path.to_string()];
    let pairs = [("/usr/bin/", "/bin/"), ("/usr/sbin/", "/sbin/"), ("/usr/lib64/", "/lib64/"), ("/usr/lib32/", "/lib32/"), ("/usr/lib/", "/lib/")];
    for (a, b) in pairs {
        if let Some(rest) = path.strip_prefix(a) {
            v.push(format!("{}{}", b, rest));
        } else if let Some(rest) = path.strip_prefix(b) {
            v.push(format!("{}{}", a, rest));
        }
    }
    // canonical form too (e.g. /lib/x86_64-linux-gnu/security -> /usr/lib/...)
    if let Ok(c) = std::fs::canonicalize(path) {
        let c = c.to_string_lossy().into_owned();
        if !v.contains(&c) {
            v.push(c);
        }
    }
    v
}

struct OwnedDb {
    pm: Pm,
    files: HashSet<String>,
    /// dpkg conffile -> md5 recorded at install time (from /var/lib/dpkg/status)
    conffiles: HashMap<String, String>,
    rpm_cache: Mutex<HashMap<String, Ownership>>,
}

fn db_cache() -> &'static Mutex<HashMap<PathBuf, Arc<OwnedDb>>> {
    static C: OnceLock<Mutex<HashMap<PathBuf, Arc<OwnedDb>>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn load_db(root: &Root) -> Arc<OwnedDb> {
    if let Some(db) = db_cache().lock().ok().and_then(|c| c.get(&root.base).cloned()) {
        return db;
    }
    let pm = detect(root);
    let mut files = HashSet::new();
    let mut conffiles = HashMap::new();
    match pm {
        Pm::Dpkg => {
            if let Some(status) = root.read_string("/var/lib/dpkg/status", 256 * 1024 * 1024) {
                let mut in_conf = false;
                for l in status.lines() {
                    if l.starts_with("Conffiles:") {
                        in_conf = true;
                        continue;
                    }
                    if in_conf && l.starts_with(' ') {
                        let f: Vec<&str> = l.split_whitespace().collect();
                        if f.len() >= 2 && f[1].len() == 32 {
                            conffiles.insert(f[0].to_string(), f[1].to_string());
                        }
                    } else {
                        in_conf = false;
                    }
                }
            }
            for name in root.read_dir("/var/lib/dpkg/info") {
                if name.ends_with(".list") {
                    if let Some(c) = root.read_string(&format!("/var/lib/dpkg/info/{}", name), 64 * 1024 * 1024) {
                        files.extend(c.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()));
                    }
                }
            }
        }
        Pm::Pacman => {
            for pkg in root.read_dir("/var/lib/pacman/local") {
                if let Some(c) = root.read_string(&format!("/var/lib/pacman/local/{}/files", pkg), 64 * 1024 * 1024) {
                    let mut in_files = false;
                    for l in c.lines() {
                        if l.starts_with('%') {
                            in_files = l == "%FILES%";
                            continue;
                        }
                        if in_files && !l.is_empty() {
                            files.insert(format!("/{}", l.trim_end_matches('/')));
                        }
                    }
                }
            }
        }
        Pm::Apk => {
            if let Some(c) = root.read_string("/lib/apk/db/installed", 256 * 1024 * 1024) {
                let mut dir = String::new();
                for l in c.lines() {
                    if let Some(d) = l.strip_prefix("F:") {
                        dir = d.to_string();
                        files.insert(format!("/{}", dir));
                    } else if let Some(f) = l.strip_prefix("R:") {
                        files.insert(format!("/{}/{}", dir, f));
                    }
                }
            }
        }
        Pm::Rpm | Pm::Unknown => {}
    }
    let db = Arc::new(OwnedDb { pm, files, conffiles, rpm_cache: Mutex::new(HashMap::new()) });
    if let Ok(mut c) = db_cache().lock() {
        c.insert(root.base.clone(), db.clone());
    }
    db
}

pub fn pm_of(root: &Root) -> Pm {
    load_db(root).pm
}

/// Is this in-root path owned by an installed package?
pub fn owner(root: &Root, path: &str) -> Ownership {
    let db = load_db(root);
    match db.pm {
        Pm::Unknown => Ownership::Unknown,
        Pm::Rpm => {
            if let Some(o) = db.rpm_cache.lock().ok().and_then(|c| c.get(path).copied()) {
                return o;
            }
            let mut result = Ownership::Unknown;
            for p in aliases(path) {
                let mut args: Vec<String> = vec!["-qf".into()];
                if !root.is_live() {
                    args.push("--root".into());
                    args.push(root.base.to_string_lossy().into_owned());
                }
                args.push(p.clone());
                let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                match util::run_cmd(&["/usr/bin/rpm", "/bin/rpm"], &a, Duration::from_secs(20), 65536, None) {
                    Some(out) if out.ok() => {
                        result = Ownership::Owned;
                        break;
                    }
                    Some(out) if !out.timed_out => result = Ownership::NotOwned,
                    _ => {}
                }
            }
            if let Ok(mut c) = db.rpm_cache.lock() {
                c.insert(path.to_string(), result);
            }
            result
        }
        _ => {
            if db.files.is_empty() {
                return Ownership::Unknown;
            }
            if aliases(path).iter().any(|p| db.files.contains(p)) {
                Ownership::Owned
            } else {
                Ownership::NotOwned
            }
        }
    }
}

/// Is this file exactly as its package shipped it? For dpkg conffiles we compare the md5
/// recorded at install time; for other package managers ownership is the best cheap signal.
/// Lets persistence checks skip stock files (e.g. Ubuntu's motd-news uses wget) while still
/// flagging the same file once an attacker edits it.
pub fn is_pristine(root: &Root, path: &str) -> bool {
    let db = load_db(root);
    if db.pm == Pm::Dpkg {
        if let Some(want) = db.conffiles.get(path) {
            return root.open(path).and_then(|(f, _)| hash::md5_reader(f, 64 * 1024 * 1024)).map(|h| &h == want).unwrap_or(false);
        }
    }
    db.pm != Pm::Unknown && owner(root, path) == Ownership::Owned && !path.starts_with("/etc/")
}

/// dpkg-divert: original path -> (where other packages' copy was moved, diverting package).
/// A diversion applies to every package except the one that made it (":" = local admin).
fn dpkg_diversions(root: &Root) -> HashMap<String, (String, String)> {
    let mut m = HashMap::new();
    if let Some(c) = root.read_string("/var/lib/dpkg/diversions", 16 * 1024 * 1024) {
        let lines: Vec<&str> = c.lines().collect();
        for t in lines.chunks(3) {
            if t.len() == 3 {
                m.insert(t[0].to_string(), (t[1].to_string(), t[2].to_string()));
            }
        }
    }
    m
}

// ───────────────────────── integrity verification ─────────────────────────

#[allow(dead_code)]
#[derive(Default, Debug)]
pub struct VerifyResult {
    pub pm: Option<Pm>,
    pub checked: usize,
    pub tampered: Vec<(String, String)>,
    pub missing: Vec<String>,
    pub note: Option<String>,
    pub timed_out: bool,
}

/// Files whose tampering matters most even in a quick scan (Ebury replaces libkeyutils,
/// PAM backdoors replace pam_unix, loaders/libc for global hooks).
pub fn is_critical(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    let file = p.rsplit('/').next().unwrap_or(p);
    let is_lib = p.contains("lib") && file.contains(".so");
    p.starts_with("bin/")
        || p.starts_with("sbin/")
        || p.starts_with("usr/bin/")
        || p.starts_with("usr/sbin/")
        || (p.contains("/security/") && is_lib)
        || is_lib
            && [
                "libpam",
                "libc.so",
                "libc-",
                "ld-linux",
                "ld-musl",
                "libdl",
                "libpthread",
                "libcrypt",
                "libnss_",
                "libaudit",
                "libselinux",
                "libkeyutils",
                "libsystemd",
                "libutil",
                "libz.so",
                "liblzma",
            ]
            .iter()
            .any(|x| file.starts_with(x))
}

/// Parse dpkg/rpm style verify flag strings: 9 chars, '5' at index 2 = digest mismatch.
pub fn parse_verify_line(line: &str) -> Option<(bool, bool, String)> {
    // returns (digest_mismatch, missing, path)
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(rest) = t.strip_prefix("missing") {
        let path = rest.trim().trim_start_matches("c ").trim();
        return Some((false, true, path.to_string()));
    }
    let flags = t.get(..9)?;
    if !flags.chars().all(|c| ".?SM5DLUGTP".contains(c)) {
        return None;
    }
    let rest = t[9..].trim();
    // optional attribute marker (c=config, d=doc, g=ghost, l=license, r=readme)
    let path = match rest.split_once(' ') {
        Some((m, p)) if m.len() == 1 => p.trim(),
        _ => rest,
    };
    Some((flags.as_bytes()[2] == b'5', false, path.to_string()))
}

pub fn verify(root: &Root, full: bool, budget: Duration) -> VerifyResult {
    let pm = detect(root);
    let mut r = VerifyResult { pm: Some(pm), ..Default::default() };
    match pm {
        Pm::Dpkg => verify_dpkg_native(root, full, budget, &mut r),
        Pm::Rpm => {
            let mut args = vec!["-Va".to_string(), "--nomtime".into(), "--nodeps".into(), "--noscripts".into()];
            if !root.is_live() {
                args.push("--root".into());
                args.push(root.base.to_string_lossy().into_owned());
            }
            let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            match util::run_cmd(&["/usr/bin/rpm", "/bin/rpm"], &a, budget, 32 * 1024 * 1024, None) {
                Some(out) => {
                    r.timed_out = out.timed_out;
                    for line in out.stdout_str().lines() {
                        if let Some((digest, missing, path)) = parse_verify_line(line) {
                            if path.starts_with("/etc/") {
                                continue;
                            }
                            if missing {
                                r.missing.push(path);
                            } else if digest && (full || is_critical(&path)) {
                                r.tampered.push((path, "rpm digest mismatch".into()));
                            }
                        }
                    }
                }
                None => r.note = Some("rpm binary not found or not root-owned".into()),
            }
        }
        Pm::Pacman => {
            let mut args = vec!["-Qkk".to_string()];
            if !root.is_live() {
                args.push("--root".into());
                args.push(root.base.to_string_lossy().into_owned());
                args.push("--dbpath".into());
                args.push(root.base.join("var/lib/pacman").to_string_lossy().into_owned());
            }
            let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            match util::run_cmd(&["/usr/bin/pacman"], &a, budget, 32 * 1024 * 1024, None) {
                Some(out) => {
                    r.timed_out = out.timed_out;
                    let text = format!("{}\n{}", out.stdout_str(), out.stderr_str());
                    for l in text.lines() {
                        if l.contains("checksum mismatch") {
                            if let Some(path) = l.split(": ").nth(2).and_then(|p| p.split(" (").next()) {
                                if !path.starts_with("/etc/") && (full || is_critical(path)) {
                                    r.tampered.push((path.to_string(), "pacman checksum mismatch".into()));
                                }
                            }
                        } else if l.contains("No such file") {
                            if let Some(path) = l.split(": ").nth(2).and_then(|p| p.split(" (").next()) {
                                r.missing.push(path.to_string());
                            }
                        }
                    }
                }
                None => r.note = Some("pacman binary not found or not root-owned".into()),
            }
        }
        Pm::Apk => {
            let mut args = vec!["audit".to_string(), "--system".into()];
            if !root.is_live() {
                args.push("--root".into());
                args.push(root.base.to_string_lossy().into_owned());
            }
            let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            match util::run_cmd(&["/sbin/apk", "/usr/bin/apk"], &a, budget, 32 * 1024 * 1024, None) {
                Some(out) => {
                    r.timed_out = out.timed_out;
                    for l in out.stdout_str().lines() {
                        if let Some(p) = l.strip_prefix("U ") {
                            let path = format!("/{}", p.trim());
                            if !path.starts_with("/etc/") && (full || is_critical(&path)) {
                                r.tampered.push((path, "apk checksum differs".into()));
                            }
                        }
                    }
                }
                None => r.note = Some("apk binary not found or not root-owned".into()),
            }
        }
        Pm::Unknown => r.note = Some("no supported package manager found".into()),
    }
    if !root.is_live() && pm != Pm::Unknown {
        let extra =
            "Verified against the target's OWN package database — an attacker with root can edit it. Use --hashdb for trustworthy offline verification.";
        r.note = Some(match r.note.take() {
            Some(n) => format!("{} {}", n, extra),
            None => extra.to_string(),
        });
    }
    r
}

fn verify_dpkg_native(root: &Root, full: bool, budget: Duration, r: &mut VerifyResult) {
    let diversions = dpkg_diversions(root);
    let mut work: Vec<(String, String)> = Vec::new(); // (path, md5)
    for name in root.read_dir("/var/lib/dpkg/info") {
        if !name.ends_with(".md5sums") {
            continue;
        }
        let owner_pkg = name.trim_end_matches(".md5sums").split(':').next().unwrap_or("").to_string();
        if let Some(c) = root.read_string(&format!("/var/lib/dpkg/info/{}", name), 64 * 1024 * 1024) {
            for line in c.lines() {
                if let Some((md5, rel)) = line.split_once("  ") {
                    let path = format!("/{}", rel.trim());
                    if path.starts_with("/etc/") || !(full || is_critical(&path)) {
                        continue;
                    }
                    // a diverted file was moved aside by another package/admin: the
                    // packaged content now lives at the diversion target
                    let path = match diversions.get(&path) {
                        Some((to, by)) if *by != owner_pkg => to.clone(),
                        _ => path,
                    };
                    work.push((path, md5.trim().to_lowercase()));
                }
            }
        }
    }
    let deadline = std::time::Instant::now() + budget;
    type Acc = (Vec<(String, String)>, Vec<String>, usize, bool);
    let results: Mutex<Acc> = Mutex::new((Vec::new(), Vec::new(), 0, false));
    let chunks: Vec<&[(String, String)]> = work.chunks(work.len().div_ceil(4).max(1)).collect();
    std::thread::scope(|s| {
        for chunk in chunks {
            let results = &results;
            s.spawn(move || {
                let mut tampered = Vec::new();
                let mut missing = Vec::new();
                let mut checked = 0;
                let mut timed_out = false;
                for (path, md5) in chunk {
                    if std::time::Instant::now() > deadline {
                        timed_out = true;
                        break;
                    }
                    // try the registered path and its usrmerge alias
                    let mut found = false;
                    for p in aliases(path) {
                        if let Some((f, meta)) = root.open(&p) {
                            found = true;
                            if meta.len() > 1024 * 1024 * 1024 {
                                break;
                            }
                            checked += 1;
                            if let Some(actual) = hash::md5_reader(f, u64::MAX) {
                                if &actual != md5 {
                                    tampered.push((path.clone(), format!("md5 {} != package {}", actual, md5)));
                                }
                            }
                            break;
                        }
                    }
                    if !found && root.lstat(path).is_none() {
                        missing.push(path.clone());
                    }
                }
                if let Ok(mut g) = results.lock() {
                    g.0.extend(tampered);
                    g.1.extend(missing);
                    g.2 += checked;
                    g.3 |= timed_out;
                }
            });
        }
    });
    let (t, m, c, to) = results.into_inner().unwrap_or_default();
    r.tampered = t;
    r.missing = m;
    r.checked = c;
    r.timed_out = to;
}

/// Verify files against a trusted hash database: JSON object {"/usr/bin/ls": "<sha256>"}.
pub fn verify_hashdb(root: &Root, db_path: &str) -> Result<VerifyResult, String> {
    let content = std::fs::read_to_string(db_path).map_err(|e| format!("cannot read hashdb: {}", e))?;
    let map: HashMap<String, String> = serde_json::from_str(&content).map_err(|e| format!("bad hashdb JSON: {}", e))?;
    let mut r = VerifyResult { note: Some(format!("verified against trusted hashdb {}", db_path)), ..Default::default() };
    for (path, want) in map {
        match root.open(&path) {
            Some((f, _)) => {
                r.checked += 1;
                if let Some(h) = hash::sha256_reader(f, u64::MAX) {
                    if !h.eq_ignore_ascii_case(&want) {
                        r.tampered.push((path, format!("sha256 {} != trusted {}", h, want)));
                    }
                }
            }
            None => r.missing.push(path),
        }
    }
    r.tampered.sort();
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_line_parsing() {
        assert_eq!(parse_verify_line("??5??????   /usr/bin/ls"), Some((true, false, "/usr/bin/ls".into())));
        assert_eq!(parse_verify_line("S.5....T.  c /etc/ssh/sshd_config"), Some((true, false, "/etc/ssh/sshd_config".into())));
        assert_eq!(parse_verify_line("..?......   /usr/lib/libfoo.so.5"), Some((false, false, "/usr/lib/libfoo.so.5".into())));
        assert_eq!(parse_verify_line("missing     /usr/share/doc/x"), Some((false, true, "/usr/share/doc/x".into())));
        assert_eq!(parse_verify_line("missing   c /etc/x.conf"), Some((false, true, "/etc/x.conf".into())));
        assert!(parse_verify_line("garbage line here").is_none());
    }

    #[test]
    fn usrmerge_aliases() {
        let a = aliases("/usr/bin/su");
        assert!(a.contains(&"/bin/su".to_string()));
        let b = aliases("/lib/x86_64-linux-gnu/security/pam_unix.so");
        assert!(b.contains(&"/usr/lib/x86_64-linux-gnu/security/pam_unix.so".to_string()));
    }

    #[test]
    fn critical_paths() {
        assert!(is_critical("/usr/sbin/sshd"));
        assert!(is_critical("/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.9"));
        assert!(is_critical("/usr/lib/x86_64-linux-gnu/security/pam_unix.so"));
        assert!(!is_critical("/usr/share/doc/bash/README"));
    }

    #[test]
    fn dpkg_native_offline() {
        let d = util::testutil::tempdir("dpkg");
        std::fs::create_dir_all(d.join("var/lib/dpkg/info")).unwrap();
        std::fs::create_dir_all(d.join("usr/bin")).unwrap();
        std::fs::write(d.join("var/lib/dpkg/status"), "").unwrap();
        std::fs::write(d.join("usr/bin/good"), b"abc").unwrap();
        std::fs::write(d.join("usr/bin/evil"), b"backdoored").unwrap();
        std::fs::write(
            d.join("var/lib/dpkg/info/coreutils.md5sums"),
            "900150983cd24fb0d6963f7d28e17f72  usr/bin/good\n900150983cd24fb0d6963f7d28e17f72  usr/bin/evil\n900150983cd24fb0d6963f7d28e17f72  usr/bin/gone\n",
        )
        .unwrap();
        std::fs::write(d.join("var/lib/dpkg/info/coreutils.list"), "/usr/bin/good\n/usr/bin/evil\n").unwrap();
        let root = Root::new(&d);
        let r = verify(&root, true, Duration::from_secs(30));
        assert_eq!(r.checked, 2);
        assert_eq!(r.tampered.len(), 1);
        assert_eq!(r.tampered[0].0, "/usr/bin/evil");
        assert_eq!(r.missing, vec!["/usr/bin/gone".to_string()]);
        assert_eq!(owner(&root, "/usr/bin/good"), Ownership::Owned);
        assert_eq!(owner(&root, "/usr/bin/nothere"), Ownership::NotOwned);
        let _ = std::fs::remove_dir_all(d);
    }
}
