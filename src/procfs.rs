//! /proc parsing helpers shared by the live modules.

use crate::util;
use std::collections::{HashMap, HashSet};
use std::fs;

#[derive(Clone, Debug, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub ppid: u32,
    pub uid: u32,
    pub exe: String,
    pub exe_deleted: bool,
}

pub fn read_cmdline(pid: u32) -> String {
    util::read_proc_bytes(format!("/proc/{}/cmdline", pid)).map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string()).unwrap_or_default()
}

pub fn read_cmdline_argv0(pid: u32) -> String {
    util::read_proc_bytes(format!("/proc/{}/cmdline", pid))
        .map(|b| {
            let first = b.split(|&c| c == 0).next().unwrap_or(&[]);
            String::from_utf8_lossy(first).into_owned()
        })
        .unwrap_or_default()
}

pub fn comm(pid: u32) -> String {
    util::read_proc(format!("/proc/{}/comm", pid)).map(|s| s.trim().to_string()).unwrap_or_default()
}

/// exe target and whether it is marked "(deleted)".
pub fn exe(pid: u32) -> (String, bool) {
    match fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(p) => {
            let s = p.to_string_lossy().into_owned();
            if let Some(stripped) = s.strip_suffix(" (deleted)") {
                (stripped.to_string(), true)
            } else {
                (s, false)
            }
        }
        Err(_) => (String::new(), false),
    }
}

pub fn status_fields(pid: u32) -> HashMap<String, String> {
    let mut m = HashMap::new();
    if let Some(s) = util::read_proc(format!("/proc/{}/status", pid)) {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once(':') {
                m.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    m
}

pub fn read_proc_info(pid: u32) -> Option<ProcInfo> {
    let st = status_fields(pid);
    if st.is_empty() {
        return None;
    }
    let (exe, exe_deleted) = exe(pid);
    Some(ProcInfo {
        pid,
        name: st.get("Name").cloned().unwrap_or_default(),
        cmdline: read_cmdline(pid),
        ppid: st.get("PPid").and_then(|v| v.parse().ok()).unwrap_or(0),
        uid: st.get("Uid").and_then(|v| v.split_whitespace().next()).and_then(|v| v.parse().ok()).unwrap_or(0),
        exe,
        exe_deleted,
    })
}

pub fn read_procs() -> Vec<ProcInfo> {
    util::proc_pids().into_iter().filter_map(read_proc_info).collect()
}

// ───────────────────────── /proc/PID/maps ─────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct MapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub inode: u64,
    pub path: String,
    pub deleted: bool,
}

impl MapEntry {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
    pub fn is_anon(&self) -> bool {
        self.path.is_empty()
    }
    pub fn is_exec(&self) -> bool {
        self.perms.as_bytes().get(2) == Some(&b'x')
    }
    pub fn is_write(&self) -> bool {
        self.perms.as_bytes().get(1) == Some(&b'w')
    }
}

/// Parse one maps line. The path is everything after the 5th field (it may contain
/// spaces) and a trailing " (deleted)" is split off. The old parser used only the 6th
/// whitespace token, so its "(deleted)" check could never fire.
pub fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let mut rest = line;
    let mut fields = Vec::with_capacity(5);
    for _ in 0..5 {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        fields.push(&rest[..end]);
        rest = &rest[end..];
    }
    let mut path = rest.trim().to_string();
    let mut deleted = false;
    if let Some(p) = path.strip_suffix(" (deleted)") {
        path = p.to_string();
        deleted = true;
    } else if path == "(deleted)" {
        path.clear();
        deleted = true;
    }
    let (s, e) = fields[0].split_once('-')?;
    Some(MapEntry {
        start: u64::from_str_radix(s, 16).ok()?,
        end: u64::from_str_radix(e, 16).ok()?,
        perms: fields[1].to_string(),
        inode: fields[4].parse().unwrap_or(0),
        path,
        deleted,
    })
}

pub fn maps(pid: u32) -> Option<Vec<MapEntry>> {
    let content = util::read_proc(format!("/proc/{}/maps", pid))?;
    Some(content.lines().filter_map(parse_maps_line).collect())
}

// ───────────────────────── file descriptors ─────────────────────────

pub fn fds(pid: u32) -> Vec<(u32, String)> {
    let mut out = Vec::new();
    let dir = format!("/proc/{}/fd", pid);
    for name in util::list_dir_raw(&dir).unwrap_or_default() {
        if let Ok(fd) = name.parse::<u32>() {
            if let Ok(t) = fs::read_link(format!("{}/{}", dir, name)) {
                out.push((fd, t.to_string_lossy().into_owned()));
            }
        }
    }
    out
}

pub fn socket_inode(target: &str) -> Option<u64> {
    target.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// inode -> (pid, comm) for every socket fd on the system.
pub fn socket_owner_map() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    for pid in util::proc_pids() {
        let fds = fds(pid);
        if fds.iter().any(|(_, t)| t.starts_with("socket:[")) {
            let name = comm(pid);
            for (_, t) in fds {
                if let Some(inode) = socket_inode(&t) {
                    map.entry(inode).or_insert((pid, name.clone()));
                }
            }
        }
    }
    map
}

pub fn pid_socket_inodes(pid: u32) -> HashSet<u64> {
    fds(pid).iter().filter_map(|(_, t)| socket_inode(t)).collect()
}

// ───────────────────────── containers ─────────────────────────

/// Best-effort container id from /proc/PID/cgroup (docker, containerd, podman, k8s, lxc).
pub fn container_of(pid: u32) -> Option<String> {
    let cg = util::read_proc(format!("/proc/{}/cgroup", pid))?;
    parse_container_id(&cg)
}

pub fn parse_container_id(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        let path = line.rsplit(':').next().unwrap_or("");
        for part in path.split('/') {
            let part = part.trim_end_matches(".scope");
            for prefix in ["docker-", "cri-containerd-", "crio-", "libpod-", ""] {
                if let Some(id) = part.strip_prefix(prefix) {
                    if id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit()) {
                        let rt = match prefix {
                            "docker-" | "" if path.contains("docker") => "docker",
                            "cri-containerd-" => "containerd",
                            "crio-" => "cri-o",
                            "libpod-" => "podman",
                            _ if path.contains("kubepods") => "k8s",
                            _ => "container",
                        };
                        return Some(format!("{}:{}", rt, &id[..12]));
                    }
                }
            }
            if let Some(name) = part.strip_prefix("lxc.payload.") {
                return Some(format!("lxc:{}", name));
            }
        }
    }
    None
}

pub fn ns_inode(pid: u32, ns: &str) -> Option<String> {
    fs::read_link(format!("/proc/{}/ns/{}", pid, ns)).ok().map(|p| p.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_parsing_handles_deleted_spaces_and_memfd() {
        let l1 = "7f1c2a000000-7f1c2a021000 r-xp 00000000 08:01 1234   /tmp/evil lib.so (deleted)";
        let m = parse_maps_line(l1).unwrap();
        assert_eq!(m.path, "/tmp/evil lib.so");
        assert!(m.deleted);
        assert!(m.is_exec());

        let l2 = "7f00-8f00 rwxp 00000000 00:00 0 ";
        let m2 = parse_maps_line(l2).unwrap();
        assert!(m2.is_anon() && m2.is_write() && m2.is_exec());
        assert_eq!(m2.size(), 0x1000);

        let l3 = "5600-5700 r-xp 00000000 00:01 99 /memfd:payload (deleted)";
        let m3 = parse_maps_line(l3).unwrap();
        assert_eq!(m3.path, "/memfd:payload");
        assert!(m3.deleted);

        let l4 = "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]";
        assert_eq!(parse_maps_line(l4).unwrap().path, "[vsyscall]");
    }

    #[test]
    fn container_ids() {
        let docker = "0::/system.slice/docker-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n";
        assert_eq!(parse_container_id(docker).unwrap(), "docker:0123456789ab");
        let k8s = "0::/kubepods/besteffort/pod1234/cri-containerd-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.scope";
        assert_eq!(parse_container_id(k8s).unwrap(), "containerd:aaaaaaaaaaaa");
        assert!(parse_container_id("0::/user.slice/user-1000.slice/session-2.scope").is_none());
    }

    #[test]
    fn socket_inode_parse() {
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("pipe:[1]"), None);
    }
}
