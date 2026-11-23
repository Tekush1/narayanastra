//! Shared helpers. Everything here assumes the host may be compromised:
//! - commands run only by absolute path, from root-owned binaries, with a clean env
//! - file reads are size-capped and refuse non-regular files (no /dev/zero traps)
//! - /proc listings use the raw getdents64 syscall so libc readdir hooks can't hide entries
//! - offline paths are resolved symlink-safely inside the target root

use std::collections::VecDeque;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Truncate to `max_chars` characters, always on a UTF-8 character boundary.
pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let t: String = s.chars().take(max_chars).collect();
        format!("{}...", t)
    }
}

pub fn is_elf(head: &[u8]) -> bool {
    head.len() >= 4 && &head[..4] == b"\x7fELF"
}

pub fn is_pe(head: &[u8]) -> bool {
    head.len() >= 2 && &head[..2] == b"MZ"
}

/// Open a file for reading only if it is a regular file. `nofollow` refuses a symlink
/// as the final component.
fn open_regular(path: &Path, nofollow: bool) -> Option<(File, Metadata)> {
    let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
    if nofollow {
        flags |= libc::O_NOFOLLOW;
    }
    let f = fs::OpenOptions::new().read(true).custom_flags(flags).open(path).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    Some((f, meta))
}

/// Read at most `cap` bytes from a regular file (follows symlinks — live system use).
pub fn read_capped(path: impl AsRef<Path>, cap: usize) -> Option<Vec<u8>> {
    let (f, _) = open_regular(path.as_ref(), false)?;
    let mut buf = Vec::new();
    f.take(cap as u64).read_to_end(&mut buf).ok()?;
    Some(buf)
}

pub fn read_string_capped(path: impl AsRef<Path>, cap: usize) -> Option<String> {
    read_capped(path, cap).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// First `n` bytes of a regular file (magic-number checks).
pub fn read_head(path: impl AsRef<Path>, n: usize) -> Option<Vec<u8>> {
    read_capped(path, n)
}

/// /proc files report size 0, so they need a plain read; still capped.
pub fn read_proc(path: impl AsRef<Path>) -> Option<String> {
    let f = File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(4 * 1024 * 1024).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

pub fn read_proc_bytes(path: impl AsRef<Path>) -> Option<Vec<u8>> {
    let f = File::open(path).ok()?;
    let mut buf = Vec::new();
    f.take(4 * 1024 * 1024).read_to_end(&mut buf).ok()?;
    Some(buf)
}

// ───────────────────────── raw directory listing ─────────────────────────

/// List a directory with raw openat+getdents64 syscalls. An LD_PRELOAD rootkit that hooks
/// libc readdir()/opendir() (libprocesshider, Jynx, Azazel...) cannot filter this view.
pub fn list_dir_raw(path: &str) -> Option<Vec<String>> {
    let c = std::ffi::CString::new(path).ok()?;
    let fd = unsafe { libc::syscall(libc::SYS_openat, libc::AT_FDCWD, c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) } as i32;
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        let n = n as usize;
        let mut off = 0usize;
        while off + 19 <= n {
            let reclen = u16::from_ne_bytes([buf[off + 16], buf[off + 17]]) as usize;
            if reclen == 0 || off + reclen > n {
                break;
            }
            let name_bytes = &buf[off + 19..off + reclen];
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = String::from_utf8_lossy(&name_bytes[..end]).into_owned();
            if name != "." && name != ".." {
                out.push(name);
            }
            off += reclen;
        }
    }
    unsafe {
        libc::syscall(libc::SYS_close, fd);
    }
    Some(out)
}

/// PIDs (thread-group leaders) visible in /proc via raw getdents64.
pub fn proc_pids() -> Vec<u32> {
    list_dir_raw("/proc").unwrap_or_default().iter().filter_map(|n| n.parse().ok()).collect()
}

// ───────────────────────── filesystem walking ─────────────────────────

pub struct WalkEntry {
    pub path: PathBuf,
    pub meta: Metadata,
}

/// Iterative walk that never follows symlinks and (optionally) stays on one filesystem.
/// `max_depth` 0 = only direct children. `limit` caps the number of entries visited.
pub fn walk(root: &Path, max_depth: usize, same_fs: bool, limit: usize, mut cb: impl FnMut(&WalkEntry)) {
    let root_dev = match fs::symlink_metadata(root) {
        Ok(m) if m.is_dir() => m.dev(),
        _ => return,
    };
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    queue.push_back((root.to_path_buf(), 0));
    let mut seen = 0usize;
    while let Some((dir, depth)) = queue.pop_front() {
        let entries = match fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > limit {
                return;
            }
            let path = entry.path();
            let meta = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let is_dir = meta.file_type().is_dir();
            let dev = meta.dev();
            cb(&WalkEntry { path: path.clone(), meta });
            if is_dir && depth < max_depth && (!same_fs || dev == root_dev) {
                // never descend into pseudo filesystems
                let p = path.to_string_lossy();
                if p.starts_with("/proc") || p.starts_with("/sys") || p.starts_with("/dev/pts") {
                    continue;
                }
                queue.push_back((path, depth + 1));
            }
        }
    }
}

// ───────────────────────── safe command execution ─────────────────────────

#[allow(dead_code)]
pub struct CmdOut {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub truncated: bool,
}

impl CmdOut {
    pub fn ok(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Find the first candidate absolute path that is a root-owned, non group/world-writable
/// regular file. A trojaned or attacker-writable binary is refused.
pub fn find_bin(candidates: &[&str]) -> Option<PathBuf> {
    for c in candidates {
        let p = Path::new(c);
        if !p.is_absolute() {
            continue;
        }
        if let Ok(meta) = fs::metadata(p) {
            if meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.mode() & 0o111 != 0 {
                return Some(p.to_path_buf());
            }
        }
    }
    None
}

fn reader_thread<R: Read + Send + 'static>(mut r: R, cap: usize) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 65536];
        let mut truncated = false;
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out.len() < cap {
                        let take = n.min(cap - out.len());
                        out.extend_from_slice(&buf[..take]);
                        if take < n {
                            truncated = true;
                        }
                    } else {
                        truncated = true; // keep draining so the child never blocks
                    }
                }
            }
        }
        (out, truncated)
    })
}

/// Run a command by absolute path with a cleared environment, a hard timeout and
/// concurrent stdout/stderr draining so a child producing large output can never block.
pub fn run_cmd(candidates: &[&str], args: &[&str], timeout: Duration, out_cap: usize, stdin_data: Option<Vec<u8>>) -> Option<CmdOut> {
    let bin = find_bin(candidates)?;
    let mut cmd = Command::new(&bin);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd.spawn().ok()?;

    let writer = stdin_data.and_then(|data| {
        child.stdin.take().map(|mut stdin| {
            std::thread::spawn(move || {
                use std::io::Write;
                let _ = stdin.write_all(&data);
            })
        })
    });
    let out_h = reader_thread(child.stdout.take()?, out_cap);
    let err_h = reader_thread(child.stderr.take()?, 1024 * 1024);

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    timed_out = true;
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break None,
        }
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    let (stdout, truncated) = out_h.join().unwrap_or_default();
    let (stderr, _) = err_h.join().unwrap_or_default();
    Some(CmdOut { code: status.and_then(|s| s.code()), stdout, stderr, timed_out, truncated })
}

// ───────────────────────── offline / multi-root access ─────────────────────────

/// A filesystem root: "/" for live scans, or a mounted (untrusted) disk for offline scans.
/// For offline roots every path is resolved component by component, and symlinks are
/// re-rooted inside the target, so an attacker's `auth.log -> /dev/zero` or
/// `etc -> /` trick can never reach the analyst's own machine.
#[derive(Clone, Debug)]
pub struct Root {
    pub base: PathBuf,
}

impl Root {
    pub fn live() -> Self {
        Root { base: PathBuf::from("/") }
    }

    pub fn new(base: impl Into<PathBuf>) -> Self {
        let base: PathBuf = base.into();
        let base = fs::canonicalize(&base).unwrap_or(base);
        Root { base }
    }

    pub fn is_live(&self) -> bool {
        self.base == Path::new("/")
    }

    /// Lexical join, for display only.
    pub fn display(&self, p: &str) -> String {
        if self.is_live() {
            p.to_string()
        } else {
            format!("{}{}", self.base.display(), if p.starts_with('/') { p.to_string() } else { format!("/{}", p) })
        }
    }

    /// Symlink-safe resolution inside the root. Returns a host path that contains no
    /// symlinks escaping the root (offline), or the plain path (live).
    pub fn resolve(&self, p: &str) -> Option<PathBuf> {
        if self.is_live() {
            return Some(PathBuf::from(if p.starts_with('/') { p.to_string() } else { format!("/{}", p) }));
        }
        let mut pending: VecDeque<String> = comps(p).into();
        let mut cur: Vec<String> = Vec::new();
        let mut hops = 0;
        while let Some(c) = pending.pop_front() {
            if c == ".." {
                cur.pop();
                continue;
            }
            let mut candidate = self.base.clone();
            for x in &cur {
                candidate.push(x);
            }
            candidate.push(&c);
            match fs::symlink_metadata(&candidate) {
                Ok(m) if m.file_type().is_symlink() => {
                    hops += 1;
                    if hops > 40 {
                        return None;
                    }
                    let target = fs::read_link(&candidate).ok()?;
                    let tstr = target.to_string_lossy().to_string();
                    let mut new_pending: VecDeque<String> = comps(&tstr).into();
                    if tstr.starts_with('/') {
                        cur.clear();
                    }
                    new_pending.extend(pending.drain(..));
                    pending = new_pending;
                }
                Ok(_) => cur.push(c),
                Err(_) => {
                    // path doesn't exist (yet) — return lexical remainder
                    cur.push(c);
                    for rest in pending.drain(..) {
                        if rest == ".." {
                            cur.pop();
                        } else {
                            cur.push(rest);
                        }
                    }
                }
            }
        }
        let mut out = self.base.clone();
        for x in cur {
            out.push(x);
        }
        Some(out)
    }

    pub fn read_capped(&self, p: &str, cap: usize) -> Option<Vec<u8>> {
        let rp = self.resolve(p)?;
        let (f, _) = open_regular(&rp, !self.is_live())?;
        let mut buf = Vec::new();
        f.take(cap as u64).read_to_end(&mut buf).ok()?;
        Some(buf)
    }

    pub fn read_string(&self, p: &str, cap: usize) -> Option<String> {
        self.read_capped(p, cap).map(|b| String::from_utf8_lossy(&b).into_owned())
    }

    pub fn open(&self, p: &str) -> Option<(File, Metadata)> {
        let rp = self.resolve(p)?;
        open_regular(&rp, !self.is_live())
    }

    /// Names in a directory (empty if missing).
    pub fn read_dir(&self, p: &str) -> Vec<String> {
        let rp = match self.resolve(p) {
            Some(r) => r,
            None => return Vec::new(),
        };
        let mut v: Vec<String> = fs::read_dir(rp).map(|it| it.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
        v.sort();
        v
    }

    /// lstat of the final component (symlinks are reported as symlinks).
    pub fn lstat(&self, p: &str) -> Option<Metadata> {
        let (parent, name) = split_parent(p);
        let rp = self.resolve(&parent)?;
        fs::symlink_metadata(rp.join(name)).ok()
    }

    pub fn readlink(&self, p: &str) -> Option<String> {
        let (parent, name) = split_parent(p);
        let rp = self.resolve(&parent)?;
        fs::read_link(rp.join(name)).ok().map(|t| t.to_string_lossy().into_owned())
    }

    pub fn exists(&self, p: &str) -> bool {
        self.lstat(p).is_some()
    }

    /// Convert a host path back to the in-root path ("/etc/passwd").
    pub fn inner(&self, host: &Path) -> String {
        if self.is_live() {
            return host.to_string_lossy().into_owned();
        }
        match host.strip_prefix(&self.base) {
            Ok(rel) => format!("/{}", rel.to_string_lossy()),
            Err(_) => host.to_string_lossy().into_owned(),
        }
    }
}

fn comps(p: &str) -> Vec<String> {
    Path::new(p)
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            Component::ParentDir => Some("..".to_string()),
            _ => None,
        })
        .collect()
}

fn split_parent(p: &str) -> (String, String) {
    let path = Path::new(p);
    let parent = path.parent().map(|x| x.to_string_lossy().into_owned()).unwrap_or_else(|| "/".into());
    let name = path.file_name().map(|x| x.to_string_lossy().into_owned()).unwrap_or_default();
    (if parent.is_empty() { "/".into() } else { parent }, name)
}

// ───────────────────────── users / groups ─────────────────────────

#[derive(Clone, Debug)]
pub struct User {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

pub fn parse_passwd(content: &str) -> Vec<User> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(User { name: f[0].to_string(), uid: f[2].parse().ok()?, gid: f[3].parse().ok()?, home: f[5].to_string(), shell: f[6].to_string() })
        })
        .collect()
}

pub fn users(root: &Root) -> Vec<User> {
    root.read_string("/etc/passwd", 4 * 1024 * 1024).map(|c| parse_passwd(&c)).unwrap_or_default()
}

pub fn has_login_shell(shell: &str) -> bool {
    let s = shell.trim();
    !(s.is_empty() || s.ends_with("nologin") || s.ends_with("/false") || s.ends_with("/sync") || s.ends_with("/shutdown") || s.ends_with("/halt"))
}

/// Homes worth checking: root, regular users (uid >= 1000) and anyone with a login shell.
pub fn interesting_homes(root: &Root) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for u in users(root) {
        if (u.uid == 0 || u.uid >= 1000 || has_login_shell(&u.shell))
            && u.uid != 65534
            && !u.home.is_empty()
            && u.home != "/"
            && u.home != "/nonexistent"
            && !out.iter().any(|(_, h)| h == &u.home)
        {
            out.push((u.name.clone(), u.home.clone()));
        }
    }
    if !out.iter().any(|(_, h)| h == "/root") {
        out.push(("root".into(), "/root".into()));
    }
    out
}

/// uids of the given user names (resolved from the root's /etc/passwd).
pub fn uids_of(root: &Root, names: &[&str]) -> Vec<u32> {
    users(root).into_iter().filter(|u| names.contains(&u.name.as_str())).map(|u| u.uid).collect()
}

pub fn gids_of(root: &Root, names: &[&str]) -> Vec<u32> {
    root.read_string("/etc/group", 4 * 1024 * 1024)
        .map(|c| {
            c.lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    if f.len() >= 3 && names.contains(&f[0]) {
                        f[2].parse().ok()
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn is_temp_path(p: &str) -> bool {
    p.starts_with("/tmp/") || p.starts_with("/var/tmp/") || p.starts_with("/dev/shm/") || p.starts_with("/run/shm/") || p.starts_with("/dev/mqueue/")
}

/// Path containing a hidden component like "/usr/lib/.x/" (not dotfiles in home config).
pub fn has_hidden_component(p: &str) -> bool {
    p.split('/').any(|c| c.starts_with('.') && c != "." && c != "..")
}

pub fn now_epoch() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[cfg(test)]
pub mod testutil {
    use std::path::PathBuf;
    pub fn tempdir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("nst-{}-{}-{}", tag, std::process::id(), nanos));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_multibyte_does_not_panic() {
        let s = "हिंदी टेक्स्ट 🔥 rootkit";
        let t = truncate(s, 5);
        assert!(t.ends_with("..."));
        assert_eq!(truncate("abc", 10), "abc");
    }

    #[test]
    fn passwd_parsing() {
        let p = "root:x:0:0:root:/root:/bin/bash\n# c\nsyslog:x:104:110::/home/syslog:/usr/sbin/nologin\nbad\nkush:x:1000:1000:K:/home/kush:/bin/zsh\n";
        let u = parse_passwd(p);
        assert_eq!(u.len(), 3);
        assert_eq!(u[1].uid, 104);
        assert!(!has_login_shell(&u[1].shell));
        assert!(has_login_shell(&u[2].shell));
    }

    #[test]
    fn list_dir_raw_matches_std() {
        let d = testutil::tempdir("raw");
        for n in ["a", "b", ".hidden", "नाम"] {
            std::fs::write(d.join(n), b"x").unwrap();
        }
        let mut raw = list_dir_raw(d.to_str().unwrap()).unwrap();
        raw.sort();
        let mut std_list: Vec<String> = std::fs::read_dir(&d).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        std_list.sort();
        assert_eq!(raw, std_list);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn offline_root_symlinks_cannot_escape() {
        let d = testutil::tempdir("root");
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::create_dir_all(d.join("var/log")).unwrap();
        std::fs::write(d.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        // absolute symlink must be re-rooted into the target, not the host
        std::os::unix::fs::symlink("/etc/passwd", d.join("var/log/auth.log")).unwrap();
        // a trap pointing at /dev/zero must not be read
        std::os::unix::fs::symlink("/dev/zero", d.join("var/log/syslog")).unwrap();
        // directory escape via ../../..
        std::os::unix::fs::symlink("../../../../../../etc", d.join("var/log/esc")).unwrap();

        let r = Root::new(&d);
        let resolved = r.resolve("/var/log/auth.log").unwrap();
        assert!(resolved.starts_with(&r.base), "{:?}", resolved);
        assert_eq!(r.read_string("/var/log/auth.log", 1000).unwrap(), "root:x:0:0::/root:/bin/sh\n");
        assert!(r.read_capped("/var/log/syslog", 1000).is_none());
        let esc = r.resolve("/var/log/esc/passwd").unwrap();
        assert!(esc.starts_with(&r.base));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn cmd_runner_drains_large_output() {
        // output larger than the 64KB pipe buffer must be drained while waiting
        if let Some(out) = run_cmd(&["/usr/bin/head", "/bin/head"], &["-c", "500000", "/dev/zero"], Duration::from_secs(10), 10 * 1024 * 1024, None) {
            assert!(!out.timed_out);
            assert_eq!(out.stdout.len(), 500000);
        }
    }
}
