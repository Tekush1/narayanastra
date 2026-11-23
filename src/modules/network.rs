use crate::config::ScanConfig;
use crate::netdiag::{self, Conn, Proto};
use crate::procfs;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const MODULE: &str = "NETWORK";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

fn owner_str(map: &HashMap<u64, (u32, String)>, inode: u64) -> String {
    map.get(&inode).map(|(pid, n)| format!("{} (PID {})", n, pid)).unwrap_or_else(|| "unknown".into())
}

/// /proc/net (seq_file) vs netlink sock_diag, in BOTH directions, TCP and UDP, v4 and v6.
/// Rootkits that hook tcp4_seq_show hide from /proc/net/tcp while netlink still sees the
/// socket, so both directions of the comparison are reported.
fn cross_view(tx: &Sender, proc_view: &[Conn], nl_view: Option<&Vec<Conn>>, owners: &HashMap<u64, (u32, String)>) {
    progress(tx, "Cross-checking sockets: netlink sock_diag vs /proc/net/{tcp,udp}{,6}...");
    let nl = match nl_view {
        Some(v) => v,
        None => {
            send(tx, Finding::new(Severity::Info, MODULE, "Port Integrity", "netlink sock_diag unavailable — cross-view skipped").subject("xview"));
            return;
        }
    };
    let key = |c: &Conn| (c.proto, c.v6, c.lport, c.inode);
    let proc_set: HashSet<_> = proc_view.iter().filter(|c| c.is_listener() || c.state == netdiag::TCP_ESTABLISHED).map(key).collect();
    let nl_set: HashSet<_> = nl.iter().filter(|c| c.is_listener() || c.state == netdiag::TCP_ESTABLISHED).map(key).collect();

    // give racing sockets a moment, then re-read both views before reporting
    let only_nl: Vec<_> = nl_set.difference(&proc_set).copied().collect();
    let only_proc: Vec<_> = proc_set.difference(&nl_set).copied().collect();
    let (only_nl, only_proc) = if only_nl.is_empty() && only_proc.is_empty() {
        (only_nl, only_proc)
    } else {
        std::thread::sleep(Duration::from_millis(150));
        let p2: HashSet<_> = netdiag::proc_net_all().iter().map(key).collect();
        let n2: HashSet<_> = netdiag::netlink_all().unwrap_or_default().iter().map(key).collect();
        (
            only_nl.into_iter().filter(|k| n2.contains(k) && !p2.contains(k)).collect::<Vec<_>>(),
            only_proc.into_iter().filter(|k| p2.contains(k) && !n2.contains(k)).collect::<Vec<_>>(),
        )
    };

    for (proto, v6, port, inode) in &only_nl {
        send(
            tx,
            Finding::new(
                Severity::Danger,
                MODULE,
                "Hidden Ports",
                &format!("{}{} port {} is visible to netlink but hidden from /proc/net — seq_show hook", proto, if *v6 { "6" } else { "" }, port),
            )
            .with_detail(&format!("Owner: {}", owner_str(owners, *inode)))
            .subject(&format!("{}:{}:{}", proto, v6, port)),
        );
    }
    for (proto, v6, port, inode) in &only_proc {
        send(
            tx,
            Finding::new(
                Severity::Warning,
                MODULE,
                "Hidden Ports",
                &format!("{}{} port {} is in /proc/net but missing from netlink", proto, if *v6 { "6" } else { "" }, port),
            )
            .with_detail(&format!("Owner: {}", owner_str(owners, *inode)))
            .subject(&format!("{}:{}:{}", proto, v6, port)),
        );
    }
    if only_nl.is_empty() && only_proc.is_empty() {
        send(
            tx,
            Finding::new(
                Severity::Safe,
                MODULE,
                "Port Integrity",
                &format!("netlink and /proc/net agree ({} listeners)", nl.iter().filter(|c| c.is_listener()).count()),
            )
            .subject("xview"),
        );
    }
}

/// Ask the kernel directly: bind() every port. EADDRINUSE on a port that no view lists
/// means a listener hidden from both /proc and netlink.
fn bind_probe(cfg: &ScanConfig, tx: &Sender, all: &[Conn]) {
    progress(tx, "Bind-probing every TCP/UDP port for listeners hidden from all views...");
    let known: HashSet<(Proto, u16)> = all.iter().map(|c| c.key()).collect();
    let first = if cfg.is_root { 1u16 } else { 1025 };
    let mut hidden = Vec::new();
    for proto in [Proto::Tcp, Proto::Udp] {
        for v6 in [false, true] {
            for port in first..=65535u16 {
                if known.contains(&(proto, port)) {
                    continue;
                }
                if netdiag::port_in_use(proto, v6, port) {
                    hidden.push((proto, v6, port));
                }
            }
        }
    }
    // re-verify against fresh views (ephemeral ports come and go)
    if !hidden.is_empty() {
        std::thread::sleep(Duration::from_millis(200));
        let mut fresh: Vec<Conn> = netdiag::proc_net_all();
        fresh.extend(netdiag::netlink_all().unwrap_or_default());
        let known2: HashSet<(Proto, u16)> = fresh.iter().map(|c| c.key()).collect();
        hidden.retain(|(p, v6, port)| !known2.contains(&(*p, *port)) && netdiag::port_in_use(*p, *v6, *port));
    }
    for (proto, v6, port) in &hidden {
        send(
            tx,
            Finding::new(
                Severity::Danger,
                MODULE,
                "Hidden Listener",
                &format!("{}{} port {} is bound (bind() → EADDRINUSE) but appears in no socket view", proto, if *v6 { "6" } else { "" }, port),
            )
            .with_detail("A kernel rootkit is hiding this socket from both /proc/net and netlink")
            .subject(&format!("bind:{}:{}:{}", proto, v6, port)),
        );
    }
    if hidden.is_empty() {
        send(tx, Finding::new(Severity::Safe, MODULE, "Bind Probe", &format!("No hidden listeners (ports {}-65535, tcp/udp, v4/v6)", first)).subject("bind"));
    }
}

fn listening_analysis(tx: &Sender, all: &[Conn], owners: &HashMap<u64, (u32, String)>) {
    progress(tx, "Analyzing listening sockets...");
    let suspicious_ports: HashSet<u16> =
        [4444, 5555, 6666, 7777, 1337, 31337, 12345, 4443, 6667, 6697, 1234, 4321, 9001, 9050, 9150, 2323, 65535].into_iter().collect();
    let mut seen = HashSet::new();
    let mut count = 0;
    for c in all.iter().filter(|c| c.is_listener()) {
        if !seen.insert((c.proto, c.lport)) {
            continue;
        }
        count += 1;
        let owner = owners.get(&c.inode);
        if suspicious_ports.contains(&c.lport) {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Suspicious Port", &format!("Listening on {} port {}", c.proto, c.lport))
                    .with_detail(&format!("Address: {}\nProcess: {}", c.local, owner_str(owners, c.inode)))
                    .subject(&format!("{}:{}", c.proto, c.lport)),
            );
        }
        // a listener owned by a binary in a temp dir or a deleted binary
        if let Some((pid, name)) = owner {
            let (exe, deleted) = procfs::exe(*pid);
            if util::is_temp_path(&exe) || deleted || exe.starts_with("/memfd:") {
                send(
                    tx,
                    Finding::new(
                        Severity::Danger,
                        MODULE,
                        "Suspicious Port",
                        &format!("{} port {} owned by {} running from {}{}", c.proto, c.lport, name, exe, if deleted { " (deleted)" } else { "" }),
                    )
                    .subject(&format!("{}:{}:exe", c.proto, c.lport))
                    .artifact(&format!("/proc/{}/exe", pid)),
                );
            }
        }
    }
    send(tx, Finding::new(Severity::Info, MODULE, "Listening", &format!("{} listening sockets", count)).subject("listening"));
}

fn outbound_analysis(tx: &Sender, all: &[Conn], owners: &HashMap<u64, (u32, String)>) {
    progress(tx, "Analyzing outbound connections...");
    let c2_ports: HashSet<u16> = [4444, 5555, 6666, 7777, 1337, 31337, 12345, 6667, 6697, 9001].into_iter().collect();
    let established: Vec<&Conn> =
        all.iter().filter(|c| c.proto == Proto::Tcp && c.state == netdiag::TCP_ESTABLISHED && !netdiag::is_loopback_or_unspec(&c.remote)).collect();
    let mut seen = HashSet::new();
    for c in &established {
        if !seen.insert((c.remote, c.rport, c.lport)) {
            continue;
        }
        if c2_ports.contains(&c.rport) {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Suspicious Outbound", &format!("Connection to {}:{} (common C2 port)", c.remote, c.rport))
                    .with_detail(&format!("Process: {}", owner_str(owners, c.inode)))
                    .subject(&format!("out:{}:{}", c.remote, c.rport)),
            );
        }
    }
    send(tx, Finding::new(Severity::Info, MODULE, "Outbound", &format!("{} established remote TCP connections", seen.len())).subject("outbound"));
}

fn is_virtual_iface(iface: &str) -> bool {
    let base = format!("/sys/class/net/{}", iface);
    let p = |x: &str| std::path::Path::new(&format!("{}/{}", base, x)).exists();
    if p("master") || p("bridge") || p("tun_flags") || !p("device") {
        return true; // bridge port, bridge, tun/tap, or no physical device behind it
    }
    let rd = |x: &str| util::read_proc(format!("{}/{}", base, x)).map(|s| s.trim().to_string());
    if rd("type").as_deref() == Some("65534") {
        return true;
    }
    matches!((rd("iflink"), rd("ifindex")), (Some(a), Some(b)) if a != b)
}

fn promiscuous_check(tx: &Sender) {
    progress(tx, "Checking for promiscuous physical interfaces...");
    for iface in util::list_dir_raw("/sys/class/net").unwrap_or_default() {
        if iface == "lo" {
            continue;
        }
        let flags = util::read_proc(format!("/sys/class/net/{}/flags", iface))
            .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        if flags & 0x100 != 0 && !is_virtual_iface(&iface) {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Promiscuous", &format!("Physical interface '{}' is in promiscuous mode — possible sniffer", iface))
                    .subject(&format!("promisc:{}", iface)),
            );
        }
    }
}

fn raw_socket_check(tx: &Sender, owners: &HashMap<u64, (u32, String)>) {
    progress(tx, "Checking for raw and packet sockets...");
    for (path, proto) in [("/proc/net/raw", "IPv4"), ("/proc/net/raw6", "IPv6")] {
        if let Some(content) = util::read_proc(path) {
            for line in content.lines().skip(1) {
                let f: Vec<&str> = line.split_whitespace().collect();
                if f.len() < 10 {
                    continue;
                }
                let protocol = f[1].rsplit(':').next().and_then(|p| u16::from_str_radix(p, 16).ok()).unwrap_or(0);
                if protocol == 1 || protocol == 58 {
                    continue; // ICMP/ICMPv6 (ping)
                }
                let inode: u64 = f[9].parse().unwrap_or(0);
                send(
                    tx,
                    Finding::new(
                        Severity::Warning,
                        MODULE,
                        "Raw Socket",
                        &format!("{} raw socket for protocol {} — sniffer/backdoor capable", proto, protocol),
                    )
                    .with_detail(&format!("Owner: {}", owner_str(owners, inode)))
                    .subject(&format!("raw:{}:{}", proto, inode)),
                );
            }
        }
    }
    // AF_PACKET sockets (tcpdump-style capture, BPFDoor uses these)
    if let Some(content) = util::read_proc("/proc/net/packet") {
        for line in content.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if let Some(inode) = f.last().and_then(|i| i.parse::<u64>().ok()) {
                let owner = owner_str(owners, inode);
                let benign = ["dhclient", "dhcpcd", "NetworkManager", "systemd-network", "wpa_supplicant", "lldpd", "tcpdump", "wireshark", "dumpcap"]
                    .iter()
                    .any(|b| owner.starts_with(b));
                send(
                    tx,
                    Finding::new(
                        if benign { Severity::Info } else { Severity::Warning },
                        MODULE,
                        "Raw Socket",
                        &format!("AF_PACKET socket owned by {}", owner),
                    )
                    .with_detail("Packet sockets see all traffic; BPFDoor-style backdoors use them to wait for magic packets")
                    .subject(&format!("packet:{}", inode)),
                );
            }
        }
    }
}

fn load_feed(cfg: &ScanConfig) -> (Vec<netdiag::FeedEntry>, Option<String>) {
    let mut paths: Vec<std::path::PathBuf> = Vec::new();
    if let Some(f) = &cfg.feed {
        paths.push(f.into());
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.to_path_buf())) {
        paths.push(dir.join("threat_feeds/c2_ips.txt"));
        paths.push(dir.join("../threat_feeds/c2_ips.txt"));
        paths.push(dir.join("../../threat_feeds/c2_ips.txt"));
    }
    paths.push("/etc/narayanastra/c2_ips.txt".into());
    paths.push("/usr/share/narayanastra/c2_ips.txt".into());
    paths.push("threat_feeds/c2_ips.txt".into());
    for p in paths {
        if let Some(c) = util::read_string_capped(&p, 32 * 1024 * 1024) {
            return (netdiag::parse_feed(&c), Some(p.display().to_string()));
        }
    }
    (Vec::new(), None)
}

fn threat_feed_check(cfg: &ScanConfig, tx: &Sender, all: &[Conn], owners: &HashMap<u64, (u32, String)>) {
    progress(tx, "Matching connections against the C2 threat feed (IPv4/IPv6/CIDR)...");
    let (feed, path) = load_feed(cfg);
    if feed.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "Threat Feed", "No threat feed loaded — skipping IP matching").subject("feed"));
        return;
    }
    let mut matched = 0;
    let mut seen = HashSet::new();
    for c in all {
        if netdiag::is_loopback_or_unspec(&c.remote) || !seen.insert((c.remote, c.rport)) {
            continue;
        }
        if netdiag::feed_matches(&feed, &c.remote) {
            matched += 1;
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "C2 Match", &format!("{} connection to known C2 {}:{}", c.proto, c.remote, c.rport))
                    .with_detail(&format!("Local port: {}\nProcess: {}", c.lport, owner_str(owners, c.inode)))
                    .subject(&format!("c2:{}:{}", c.remote, c.rport)),
            );
        }
    }
    if matched == 0 {
        send(
            tx,
            Finding::new(Severity::Safe, MODULE, "C2 Check", &format!("No connections to {} feed entries ({})", feed.len(), path.unwrap_or_default()))
                .subject("c2"),
        );
    }
}

pub fn scan(cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    let proc_view = netdiag::proc_net_all();
    let nl_view = netdiag::netlink_all();
    let owners = procfs::socket_owner_map();
    let mut all = proc_view.clone();
    if let Some(nl) = &nl_view {
        let have: HashSet<_> = all.iter().map(|c| (c.proto, c.v6, c.lport, c.inode)).collect();
        all.extend(nl.iter().filter(|c| !have.contains(&(c.proto, c.v6, c.lport, c.inode))).cloned());
    }

    cross_view(&tx, &proc_view, nl_view.as_ref(), &owners);
    if cfg.full {
        bind_probe(cfg, &tx, &all);
    }
    listening_analysis(&tx, &all, &owners);
    outbound_analysis(&tx, &all, &owners);
    promiscuous_check(&tx);
    raw_socket_check(&tx, &owners);
    threat_feed_check(cfg, &tx, &all, &owners);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
