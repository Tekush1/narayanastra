//! Baselines and cross-view diffs.
//!
//! `baseline save`  — snapshot hashes of binaries, SUIDs, persistence files, users, and
//!                    (live) listeners / modules / eBPF programs. Optionally HMAC-signed.
//! `baseline diff`  — report only what changed since the snapshot.
//! `crossdiff`      — compare a LIVE snapshot with an OFFLINE snapshot of the same disk:
//!                    anything on disk that the running OS doesn't show is being hidden.

use crate::hash;
use crate::netdiag;
use crate::pkg;
use crate::procfs;
use crate::report::{Finding, ScanReport, Severity};
use crate::util::{self, Root};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;

const MODULE: &str = "BASELINE";

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Snapshot {
    pub version: String,
    pub created: String,
    pub host: String,
    pub root: String,
    pub live: bool,
    pub files: BTreeMap<String, String>,
    pub suid: BTreeSet<String>,
    pub persistence: BTreeMap<String, String>,
    pub users: BTreeSet<String>,
    pub listeners: BTreeSet<String>,
    pub modules: BTreeSet<String>,
    pub bpf: BTreeSet<String>,
    #[serde(default)]
    pub hmac: Option<String>,
}

fn hash_file(root: &Root, p: &str) -> Option<String> {
    let (f, meta) = root.open(p)?;
    if meta.len() > 512 * 1024 * 1024 {
        return Some(format!("size:{}", meta.len()));
    }
    hash::sha256_reader(f, u64::MAX)
}

fn walk_root(root: &Root, dir: &str, depth: usize, mut cb: impl FnMut(&str, &std::fs::Metadata)) {
    let base = match root.resolve(dir) {
        Some(b) => b,
        None => return,
    };
    util::walk(&base, depth, true, 2_000_000, |e| {
        let inner = root.inner(&e.path);
        cb(&inner, &e.meta);
    });
}

const PERSIST_FILES: [&str; 12] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/crontab",
    "/etc/ld.so.preload",
    "/etc/rc.local",
    "/etc/profile",
    "/etc/bash.bashrc",
    "/etc/environment",
    "/etc/ssh/sshd_config",
    "/etc/modules",
];
const PERSIST_DIRS: [&str; 18] = [
    "/etc/sudoers.d",
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/profile.d",
    "/etc/pam.d",
    "/etc/udev/rules.d",
    "/etc/update-motd.d",
    "/etc/modules-load.d",
    "/etc/modprobe.d",
    "/etc/ld.so.conf.d",
    "/etc/xdg/autostart",
    "/etc/ssh/sshd_config.d",
];

pub fn take(root: &Root, full: bool) -> Snapshot {
    let mut s = Snapshot {
        version: crate::report::VERSION.to_string(),
        created: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        host: root.read_string("/etc/hostname", 4096).unwrap_or_default().trim().to_string(),
        root: root.base.display().to_string(),
        live: root.is_live(),
        ..Default::default()
    };
    // binaries + security modules + critical libraries
    for dir in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"] {
        walk_root(root, dir, 0, |p, m| {
            if m.file_type().is_file() {
                if let Some(h) = hash_file(root, p) {
                    s.files.insert(p.to_string(), h);
                }
            }
        });
    }
    for dir in ["/usr/lib", "/usr/lib64", "/lib64"] {
        walk_root(root, dir, if full { 6 } else { 2 }, |p, m| {
            if m.file_type().is_file() && (p.contains("/security/") || pkg::is_critical(p) || (full && p.contains(".so"))) {
                if let Some(h) = hash_file(root, p) {
                    s.files.insert(p.to_string(), h);
                }
            }
        });
    }
    if full {
        for dir in ["/boot", "/lib/modules", "/usr/lib/modules"] {
            walk_root(root, dir, 12, |p, m| {
                if m.file_type().is_file() {
                    if let Some(h) = hash_file(root, p) {
                        s.files.insert(p.to_string(), h);
                    }
                }
            });
        }
    }
    // SUID/SGID everywhere that matters
    for dir in ["/usr", "/opt", "/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/srv", "/var/www"] {
        walk_root(root, dir, if full { 32 } else { 6 }, |p, m| {
            if m.file_type().is_file() && m.mode() & 0o6000 != 0 {
                s.suid.insert(p.to_string());
            }
        });
    }
    // persistence-relevant files
    let mut pfiles: Vec<String> = PERSIST_FILES.iter().map(|s| s.to_string()).collect();
    for d in PERSIST_DIRS {
        walk_root(root, d, 2, |p, m| {
            if m.file_type().is_file() {
                pfiles.push(p.to_string());
            }
        });
    }
    for (_, home) in util::interesting_homes(root) {
        for f in [".ssh/authorized_keys", ".ssh/authorized_keys2", ".bashrc", ".profile", ".bash_profile", ".zshrc"] {
            pfiles.push(format!("{}/{}", home, f));
        }
        walk_root(root, &format!("{}/.config/systemd/user", home), 2, |p, m| {
            if m.file_type().is_file() {
                pfiles.push(p.to_string());
            }
        });
    }
    for p in pfiles {
        if let Some(h) = hash_file(root, &p) {
            s.persistence.insert(p, h);
        }
    }
    for u in util::users(root) {
        s.users.insert(format!("{}:{}:{}:{}", u.name, u.uid, u.gid, u.shell));
    }
    if root.is_live() {
        let owners = procfs::socket_owner_map();
        let conns = netdiag::netlink_all().unwrap_or_else(netdiag::proc_net_all);
        for c in conns.iter().filter(|c| c.is_listener()) {
            let exe = owners.get(&c.inode).map(|(pid, _)| procfs::exe(*pid).0).unwrap_or_default();
            s.listeners.insert(format!("{}:{}:{}", c.proto, c.lport, exe));
        }
        if let Some(m) = util::read_proc("/proc/modules") {
            s.modules.extend(m.lines().filter_map(|l| l.split_whitespace().next().map(String::from)));
        }
        if let Some(ks) = util::read_proc("/proc/kallsyms") {
            for l in ks.lines().filter(|l| l.ends_with("[bpf]")) {
                if let Some(sym) = l.split_whitespace().nth(2) {
                    if let Some(rest) = sym.strip_prefix("bpf_prog_") {
                        s.bpf.insert(rest.to_string());
                    }
                }
            }
        }
    }
    s
}

fn canonical(s: &Snapshot) -> String {
    let mut c = s.clone();
    c.hmac = None;
    serde_json::to_string(&c).unwrap_or_default()
}

pub fn sign(s: &mut Snapshot, key: &[u8]) {
    s.hmac = Some(hash::hex(&hash::hmac_sha256(key, canonical(s).as_bytes())));
}

pub fn verify_sig(s: &Snapshot, key: &[u8]) -> bool {
    match &s.hmac {
        Some(h) => *h == hash::hex(&hash::hmac_sha256(key, canonical(s).as_bytes())),
        None => false,
    }
}

pub fn load(path: &str) -> Result<Snapshot, String> {
    let c = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
    serde_json::from_str(&c).map_err(|e| format!("{} is not a Narayanastra snapshot: {}", path, e))
}

fn f(sev: Severity, cat: &str, msg: String, subject: &str) -> Finding {
    Finding::new(sev, MODULE, cat, &msg).subject(subject)
}

fn diff_maps(out: &mut Vec<Finding>, old: &BTreeMap<String, String>, new: &BTreeMap<String, String>, label: &str, changed: Severity, added: Severity) {
    for (p, h) in new {
        match old.get(p) {
            Some(oh) if oh != h => out.push(
                f(changed, &format!("{} Changed", label), format!("{} changed: {}", label, p), p).with_detail(&format!("was {}\nnow {}", oh, h)).artifact(p),
            ),
            None => out.push(f(added, &format!("{} Added", label), format!("New {}: {}", label.to_lowercase(), p), p).artifact(p)),
            _ => {}
        }
    }
    for p in old.keys().filter(|p| !new.contains_key(*p)) {
        out.push(f(Severity::Info, &format!("{} Removed", label), format!("{} removed: {}", label, p), p));
    }
}

fn diff_sets(out: &mut Vec<Finding>, old: &BTreeSet<String>, new: &BTreeSet<String>, label: &str, added: Severity) {
    for x in new.difference(old) {
        out.push(f(added, &format!("{} Added", label), format!("New {}: {}", label.to_lowercase(), x), x));
    }
    for x in old.difference(new) {
        out.push(f(Severity::Info, &format!("{} Removed", label), format!("{} gone: {}", label, x), x));
    }
}

/// Changes between a saved baseline and now.
pub fn diff(old: &Snapshot, new: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    diff_maps(&mut out, &old.files, &new.files, "Binary", Severity::Danger, Severity::Warning);
    diff_maps(&mut out, &old.persistence, &new.persistence, "Persistence File", Severity::Warning, Severity::Warning);
    diff_sets(&mut out, &old.suid, &new.suid, "SUID", Severity::Danger);
    for u in new.users.difference(&old.users) {
        let uid0 = u.split(':').nth(1) == Some("0");
        out.push(f(if uid0 { Severity::Danger } else { Severity::Warning }, "New Account", format!("Account added/changed: {}", u), u));
    }
    if old.live && new.live {
        diff_sets(&mut out, &old.listeners, &new.listeners, "Listener", Severity::Warning);
        diff_sets(&mut out, &old.modules, &new.modules, "Kernel Module", Severity::Warning);
        diff_sets(&mut out, &old.bpf, &new.bpf, "eBPF Program", Severity::Info);
    }
    if out.is_empty() {
        out.push(f(Severity::Safe, "Baseline", "No changes since the baseline".into(), "nochange"));
    }
    out
}

/// LIVE vs OFFLINE: what does the disk contain that the running OS hid or faked?
pub fn crossdiff(live: &Snapshot, offline: &Snapshot) -> Vec<Finding> {
    let mut out = Vec::new();
    type HashMapRef<'a> = &'a BTreeMap<String, String>;
    let pairs: [(HashMapRef, HashMapRef, &str); 2] = [(&live.files, &offline.files, "file"), (&live.persistence, &offline.persistence, "persistence file")];
    for (l, o, label) in pairs {
        for (p, oh) in o {
            match l.get(p) {
                None => out.push(
                    f(
                        Severity::Danger,
                        "Hidden From Live OS",
                        format!("{} exists on disk but was invisible to the running system: {}", label, p),
                        &format!("hidden:{}", p),
                    )
                    .with_detail(&format!("offline sha256 {}", oh))
                    .mitre("T1014")
                    .artifact(p),
                ),
                Some(lh) if lh != oh => out.push(
                    f(
                        Severity::Danger,
                        "Content Mismatch",
                        format!("Running system served different content for {} than the disk holds", p),
                        &format!("mismatch:{}", p),
                    )
                    .with_detail(&format!(
                        "live    {}\noffline {}\nA read/VFS hook can show a clean copy to scanners. (Rule out legit changes between the two snapshots.)",
                        lh, oh
                    ))
                    .mitre("T1014")
                    .artifact(p),
                ),
                _ => {}
            }
        }
        for p in l.keys().filter(|p| !o.contains_key(*p)) {
            out.push(f(
                Severity::Warning,
                "Live Only",
                format!("{} visible live but not on disk (overlay/tmpfs/deleted since): {}", label, p),
                &format!("liveonly:{}", p),
            ));
        }
    }
    for x in offline.suid.difference(&live.suid) {
        out.push(
            f(Severity::Danger, "Hidden From Live OS", format!("SUID file on disk hidden from the running system: {}", x), &format!("suid:{}", x))
                .mitre("T1014")
                .artifact(x),
        );
    }
    for x in offline.users.difference(&live.users) {
        out.push(
            f(
                Severity::Danger,
                "Hidden From Live OS",
                format!("Account in the on-disk passwd that the live system didn't show: {}", x),
                &format!("user:{}", x),
            )
            .mitre("T1014"),
        );
    }
    if out.is_empty() {
        out.push(f(
            Severity::Safe,
            "Crossdiff",
            format!("Live and offline views agree ({} files, {} persistence files)", offline.files.len(), offline.persistence.len()),
            "agree",
        ));
    }
    out
}

pub fn to_markdown(findings: &[Finding]) -> String {
    let mut s = String::from("| Severity | Category | Finding | Detail |\n|---|---|---|---|\n");
    for x in findings {
        s.push_str(&format!(
            "| {:?} | {} | {} | {} |\n",
            x.severity,
            x.category,
            x.message.replace('|', "\\|"),
            x.detail.clone().unwrap_or_default().replace('\n', "<br>").replace('|', "\\|")
        ));
    }
    s
}

pub fn to_csv(findings: &[Finding]) -> String {
    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let mut s = String::from("severity,category,message,detail,artifact\n");
    for x in findings {
        s.push_str(&format!(
            "{},{},{},{},{}\n",
            q(&format!("{:?}", x.severity)),
            q(&x.category),
            q(&x.message),
            q(&x.detail.clone().unwrap_or_default()),
            q(&x.artifact.clone().unwrap_or_default())
        ));
    }
    s
}

pub fn report_for(findings: Vec<Finding>, mode: &str) -> ScanReport {
    let host = util::read_string_capped("/etc/hostname", 4096).unwrap_or_default().trim().to_string();
    let mut r = ScanReport::new(mode.to_string(), host, std::env::var("USER").unwrap_or_default());
    r.findings = findings;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap() -> Snapshot {
        let mut s = Snapshot { live: true, ..Default::default() };
        s.files.insert("/usr/bin/ls".into(), "aa".into());
        s.files.insert("/usr/bin/ps".into(), "bb".into());
        s.users.insert("root:0:0:/bin/bash".into());
        s
    }

    #[test]
    fn diff_detects_changes_and_signing() {
        let old = snap();
        let mut new = snap();
        new.files.insert("/usr/bin/ps".into(), "evil".into());
        new.suid.insert("/tmp/.x".into());
        new.users.insert("toor:0:0:/bin/bash".into());
        let d = diff(&old, &new);
        assert!(d.iter().any(|f| f.category == "Binary Changed" && f.severity == Severity::Danger));
        assert!(d.iter().any(|f| f.category == "SUID Added" && f.severity == Severity::Danger));
        assert!(d.iter().any(|f| f.category == "New Account" && f.severity == Severity::Danger));

        let mut signed = snap();
        sign(&mut signed, b"secret");
        assert!(verify_sig(&signed, b"secret"));
        signed.files.insert("/usr/bin/ls".into(), "tampered".into());
        assert!(!verify_sig(&signed, b"secret"));
    }

    #[test]
    fn crossdiff_hidden_and_mismatch() {
        let live = snap();
        let mut off = snap();
        off.live = false;
        off.files.insert("/usr/bin/ps".into(), "real".into());
        off.files.insert("/usr/lib/.rk/libhide.so".into(), "cc".into());
        off.suid.insert("/var/tmp/.s".into());
        let d = crossdiff(&live, &off);
        assert!(d.iter().any(|f| f.category == "Content Mismatch"));
        assert_eq!(d.iter().filter(|f| f.category == "Hidden From Live OS").count(), 2);
        assert!(to_markdown(&d).contains("| Danger |"));
        assert!(to_csv(&d).lines().count() > 1);
    }
}
