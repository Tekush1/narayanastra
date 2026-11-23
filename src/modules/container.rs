//! Container awareness: which containers are running, which ones can escape.

use crate::config::ScanConfig;
use crate::procfs;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util;
use std::collections::{BTreeMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

const MODULE: &str = "CONTAINER";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

const CAP_SYS_ADMIN: u32 = 21;
const CAP_SYS_MODULE: u32 = 16;
const CAP_SYS_PTRACE: u32 = 19;

pub fn caps(hex: &str) -> u64 {
    u64::from_str_radix(hex.trim(), 16).unwrap_or(0)
}

pub fn scan(_cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    progress(&tx, "Mapping processes to containers and checking escape paths...");

    let host_net = procfs::ns_inode(1, "net");
    let host_pid = procfs::ns_inode(1, "pid");
    let host_mnt = procfs::ns_inode(1, "mnt");
    // major:minor of the host's root filesystem
    let host_root_dev: Option<String> = util::read_proc("/proc/1/mountinfo").and_then(|mi| {
        mi.lines().find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() > 4 && f[4] == "/" {
                Some(f[2].to_string())
            } else {
                None
            }
        })
    });
    let mut containers: BTreeMap<String, Vec<u32>> = BTreeMap::new();
    for pid in util::proc_pids() {
        if let Some(id) = procfs::container_of(pid) {
            containers.entry(id).or_default().push(pid);
        }
    }
    let mut reported: HashSet<(String, &str)> = HashSet::new();
    for (id, pids) in &containers {
        for pid in pids {
            let st = procfs::status_fields(*pid);
            let eff = caps(st.get("CapEff").map(|s| s.as_str()).unwrap_or("0"));
            let all_caps = eff.count_ones() >= 38;
            if all_caps && reported.insert((id.clone(), "priv")) {
                send(
                    &tx,
                    Finding::new(Severity::Warning, MODULE, "Privileged Container", &format!("Container {} runs with all capabilities (--privileged)", id))
                        .with_detail(&format!("PID {} CapEff={:x} — can load kernel modules, mount the host disk and escape", pid, eff))
                        .subject(&format!("{}:priv", id)),
                );
            } else if !all_caps && eff & ((1 << CAP_SYS_ADMIN) | (1 << CAP_SYS_MODULE) | (1 << CAP_SYS_PTRACE)) != 0 && reported.insert((id.clone(), "caps")) {
                send(
                    &tx,
                    Finding::new(
                        Severity::Warning,
                        MODULE,
                        "Privileged Container",
                        &format!("Container {} has dangerous capabilities (SYS_ADMIN/SYS_MODULE/SYS_PTRACE)", id),
                    )
                    .with_detail(&format!("PID {} CapEff={:x}", pid, eff))
                    .subject(&format!("{}:caps", id)),
                );
            }
            for (ns, host, label) in [("net", &host_net, "network"), ("pid", &host_pid, "PID"), ("mnt", &host_mnt, "mount")] {
                if host.is_some() && procfs::ns_inode(*pid, ns) == *host && reported.insert((id.clone(), label)) {
                    send(
                        &tx,
                        Finding::new(
                            if ns == "mnt" { Severity::Danger } else { Severity::Warning },
                            MODULE,
                            "Host Namespace",
                            &format!("Container {} shares the host {} namespace", id, label),
                        )
                        .subject(&format!("{}:ns:{}", id, ns)),
                    );
                }
            }
            if let Some(mi) = util::read_proc(format!("/proc/{}/mountinfo", pid)) {
                for sock in ["docker.sock", "containerd.sock", "crio.sock", "podman.sock"] {
                    if mi.contains(sock) && reported.insert((id.clone(), "sock")) {
                        send(
                            &tx,
                            Finding::new(Severity::Danger, MODULE, "Docker Socket", &format!("Container {} has the runtime socket {} mounted", id, sock))
                                .with_detail("Anyone in this container can start a privileged container and own the host")
                                .subject(&format!("{}:sock", id)),
                        );
                    }
                }
                let host_root = host_root_dev.as_deref();
                if host_root.is_some()
                    && mi.lines().any(|l| {
                        let f: Vec<&str> = l.split_whitespace().collect();
                        f.len() > 4 && Some(f[2]) == host_root && f[3] == "/" && f[4] != "/"
                    })
                    && reported.insert((id.clone(), "hostroot"))
                {
                    send(
                        &tx,
                        Finding::new(Severity::Warning, MODULE, "Host Namespace", &format!("Container {} bind-mounts the host root filesystem", id))
                            .subject(&format!("{}:hostroot", id)),
                    );
                }
            }
        }
    }
    for sock in ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock"] {
        if let Ok(m) = std::fs::metadata(sock) {
            if m.mode() & 0o002 != 0 {
                send(
                    &tx,
                    Finding::new(Severity::Danger, MODULE, "Docker Socket", &format!("{} is world-writable — any local user is root", sock))
                        .subject(&format!("perm:{}", sock)),
                );
            }
        }
    }
    let list: Vec<String> = containers.iter().map(|(k, v)| format!("{} ({} procs)", k, v.len())).collect();
    send(
        &tx,
        Finding::new(Severity::Info, MODULE, "Containers", &format!("{} running container(s)", containers.len()))
            .with_detail(&list.join("\n"))
            .subject("inventory"),
    );
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
