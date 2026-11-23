//! io_uring abuse detection.
//!
//! Rootkits like ARMO's "Curing" PoC do all of their file and network I/O through
//! io_uring rings instead of system calls, so syscall-hooking EDRs (Falco, Tetragon,
//! Defender for Linux) never see it. We don't watch syscalls at all — we look at state:
//! which processes own io_uring instances, whether they use SQPOLL kernel threads, and
//! what else those processes are doing (sockets, shells, odd binaries).

use crate::config::ScanConfig;
use crate::netdiag;
use crate::pkg::{self, Ownership};
use crate::procfs;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use std::collections::{HashMap, HashSet};
use std::time::Instant;

const MODULE: &str = "IOURING";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

#[allow(dead_code)]
#[derive(Debug, Default, Clone)]
pub struct RingInfo {
    pub fd: u32,
    pub sq_thread: Option<i64>,
    pub user_files: u64,
    pub user_bufs: u64,
}

pub fn parse_fdinfo(fd: u32, content: &str) -> RingInfo {
    let mut r = RingInfo { fd, ..Default::default() };
    for line in content.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let v = v.trim();
            match k.trim() {
                "SqThread" => r.sq_thread = v.parse().ok(),
                "UserFiles" => r.user_files = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0),
                "UserBufs" => r.user_bufs = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0),
                _ => {}
            }
        }
    }
    r
}

/// Runtimes/apps that legitimately use io_uring heavily.
const KNOWN_URING_USERS: [&str; 14] =
    ["qemu", "postgres", "mariadbd", "mysqld", "scylla", "redpanda", "nginx", "fio", "tigerbeetle", "seastar", "rocksdb", "ceph-osd", "samba", "smbd"];

pub fn scan(_cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    let root = Root::live();

    let disabled = util::read_proc("/proc/sys/kernel/io_uring_disabled").map(|s| s.trim().to_string());
    match disabled.as_deref() {
        Some("2") => {
            send(&tx, Finding::new(Severity::Safe, MODULE, "io_uring", "io_uring is disabled system-wide (kernel.io_uring_disabled=2)").subject("sysctl"))
        }
        Some("1") => send(
            &tx,
            Finding::new(Severity::Info, MODULE, "io_uring", "io_uring restricted to privileged/io_uring_group users (kernel.io_uring_disabled=1)")
                .subject("sysctl"),
        ),
        Some(_) => {
            send(&tx, Finding::new(Severity::Info, MODULE, "io_uring", "io_uring is enabled for all users (kernel.io_uring_disabled=0)").subject("sysctl"))
        }
        None => {}
    }

    progress(&tx, "Enumerating io_uring instances via /proc/*/fdinfo...");
    let conns = netdiag::netlink_all().unwrap_or_else(netdiag::proc_net_all);
    let remote_inodes: HashSet<u64> =
        conns.iter().filter(|c| c.state == netdiag::TCP_ESTABLISHED && !netdiag::is_loopback_or_unspec(&c.remote)).map(|c| c.inode).collect();
    let listen_inodes: HashSet<u64> = conns.iter().filter(|c| c.is_listener()).map(|c| c.inode).collect();

    let mut users: Vec<(u32, String, Vec<RingInfo>)> = Vec::new();
    for pid in util::proc_pids() {
        let fds = procfs::fds(pid);
        let rings: Vec<RingInfo> = fds
            .iter()
            .filter(|(_, t)| t == "anon_inode:[io_uring]")
            .map(|(fd, _)| parse_fdinfo(*fd, &util::read_proc(format!("/proc/{}/fdinfo/{}", pid, fd)).unwrap_or_default()))
            .collect();
        if rings.is_empty() {
            continue;
        }
        users.push((pid, procfs::comm(pid), rings));
    }

    // SQPOLL kernel threads ("iou-sqp-<pid>") also show up as tasks of the owner
    let mut sqpoll_owners: HashMap<u32, usize> = HashMap::new();
    for pid in util::proc_pids() {
        for tid in util::list_dir_raw(&format!("/proc/{}/task", pid)).unwrap_or_default() {
            if let Some(c) = util::read_proc(format!("/proc/{}/task/{}/comm", pid, tid)) {
                if c.trim().starts_with("iou-sqp-") {
                    *sqpoll_owners.entry(pid).or_default() += 1;
                }
            }
        }
    }

    let mut flagged = 0;
    for (pid, name, rings) in &users {
        let (exe, deleted) = procfs::exe(*pid);
        let socks = procfs::pid_socket_inodes(*pid);
        let has_remote = socks.iter().any(|i| remote_inodes.contains(i));
        let has_listen = socks.iter().any(|i| listen_inodes.contains(i));
        let fds = procfs::fds(*pid);
        let stdio_socket = fds.iter().any(|(fd, t)| *fd <= 2 && t.starts_with("socket:["));
        let sqpoll = rings.iter().any(|r| r.sq_thread.map(|t| t >= 0).unwrap_or(false)) || sqpoll_owners.contains_key(pid);
        let known = KNOWN_URING_USERS.iter().any(|k| name.to_lowercase().contains(k));
        let owned = if exe.is_empty() { Ownership::Unknown } else { pkg::owner(&root, &exe) };
        let odd_exe = deleted || exe.starts_with("/memfd:") || util::is_temp_path(&exe) || util::has_hidden_component(&exe);

        let mut reasons = Vec::new();
        if odd_exe {
            reasons.push(format!("binary is {}", if deleted { "deleted from disk" } else { "in a temp/hidden/memfd location" }));
        }
        if stdio_socket {
            reasons.push("stdin/stdout is a network socket".to_string());
        }
        if has_remote {
            reasons.push("holds an established remote TCP connection".to_string());
        }
        if has_listen {
            reasons.push("owns a listening socket".to_string());
        }
        if sqpoll {
            reasons.push("uses an SQPOLL kernel thread (I/O with zero syscalls)".to_string());
        }
        if owned == Ownership::NotOwned {
            reasons.push("binary is not owned by any package".to_string());
        }

        let sev = if odd_exe || stdio_socket {
            Severity::Danger
        } else if !known && owned != Ownership::Owned && (has_remote || sqpoll) {
            Severity::Warning
        } else {
            Severity::Info
        };
        if sev >= Severity::Warning {
            flagged += 1;
        }
        let detail = format!(
            "Exe: {}{}\nRings: {} (registered files {}, buffers {})\nSignals: {}",
            exe,
            if deleted { " (deleted)" } else { "" },
            rings.len(),
            rings.iter().map(|r| r.user_files).sum::<u64>(),
            rings.iter().map(|r| r.user_bufs).sum::<u64>(),
            if reasons.is_empty() { "none".to_string() } else { reasons.join("; ") }
        );
        send(
            &tx,
            Finding::new(
                sev,
                MODULE,
                "io_uring",
                &format!(
                    "PID {} ({}) owns {} io_uring instance(s){}",
                    pid,
                    name,
                    rings.len(),
                    if sev >= Severity::Warning { " — syscall-less I/O channel" } else { "" }
                ),
            )
            .with_detail(&detail)
            .subject(&format!("pid:{}", pid))
            .artifact(&format!("/proc/{}/exe", pid)),
        );
    }
    if users.is_empty() {
        send(&tx, Finding::new(Severity::Safe, MODULE, "io_uring", "No process currently owns an io_uring instance").subject("none"));
    } else if flagged == 0 {
        send(&tx, Finding::new(Severity::Safe, MODULE, "io_uring", &format!("{} io_uring user(s), none suspicious", users.len())).subject("summary"));
    }
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fdinfo_parsing() {
        let c = "pos:\t0\nflags:\t02000002\nmnt_id:\t15\nino:\t1057\nSqMask:\t0x3f\nSqHead:\t0\nSqTail:\t0\nCachedSqHead:\t0\nCqMask:\t0x7f\nSqThread:\t4242\nSqThreadCpu:\t-1\nUserFiles:\t2\n    0: socket:[123]\nUserBufs:\t0\n";
        let r = parse_fdinfo(5, c);
        assert_eq!(r.sq_thread, Some(4242));
        assert_eq!(r.user_files, 2);
        let r2 = parse_fdinfo(3, "SqThread:\t-1\n");
        assert_eq!(r2.sq_thread, Some(-1));
    }
}
