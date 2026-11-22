use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::fs;
use std::process::Command;
use std::time::Instant;
use std::collections::HashMap;

const MODULE: &str = "NETWORK";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn hex_to_ip(hex: &str) -> Option<String> {
    if hex.len() == 8 {
        // IPv4
        let bytes: Vec<u8> = (0..4)
            .map(|i| u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap_or(0))
            .collect();
        Some(format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]))
    } else {
        None
    }
}

fn hex_to_port(hex: &str) -> u16 {
    u16::from_str_radix(hex, 16).unwrap_or(0)
}

#[derive(Debug)]
#[allow(dead_code)]
struct RawConnection {
    local_ip: String,
    local_port: u16,
    remote_ip: String,
    remote_port: u16,
    state: u8,
    inode: u64,
}

fn parse_proc_net_tcp() -> Vec<RawConnection> {
    let mut conns = Vec::new();

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 10 {
                    continue;
                }

                let local_parts: Vec<&str> = parts[1].split(':').collect();
                let remote_parts: Vec<&str> = parts[2].split(':').collect();

                if local_parts.len() != 2 || remote_parts.len() != 2 {
                    continue;
                }

                let local_ip = hex_to_ip(local_parts[0]).unwrap_or_else(|| local_parts[0].to_string());
                let local_port = hex_to_port(local_parts[1]);
                let remote_ip = hex_to_ip(remote_parts[0]).unwrap_or_else(|| remote_parts[0].to_string());
                let remote_port = hex_to_port(remote_parts[1]);
                let state = u8::from_str_radix(parts[3], 16).unwrap_or(0);
                let inode = parts[9].parse().unwrap_or(0);

                conns.push(RawConnection {
                    local_ip, local_port, remote_ip, remote_port, state, inode,
                });
            }
        }
    }

    conns
}

fn ss_vs_proc_compare(tx: &Sender) {
    progress(tx, "Comparing ss output vs /proc/net/tcp (hidden port detection)...");

    let proc_conns = parse_proc_net_tcp();
    let proc_listening: Vec<u16> = proc_conns.iter()
        .filter(|c| c.state == 10) // LISTEN state
        .map(|c| c.local_port)
        .collect();

    // Get ss listening ports
    let mut ss_listening = Vec::new();
    if let Ok(output) = Command::new("ss").args(["-tlnH"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let addr = parts[3];
                if let Some(colon) = addr.rfind(':') {
                    if let Ok(port) = addr[colon+1..].parse::<u16>() {
                        ss_listening.push(port);
                    }
                }
            }
        }
    }

    // Ports in /proc but NOT in ss = potentially hidden by rootkit
    let hidden: Vec<u16> = proc_listening.iter()
        .filter(|p| !ss_listening.contains(p) && **p > 0)
        .copied()
        .collect();

    if !hidden.is_empty() {
        send(tx, Finding::new(Severity::Danger, MODULE, "Hidden Ports",
            &format!("{} port(s) in /proc/net/tcp but hidden from ss — rootkit may be hiding connections", hidden.len()))
            .with_detail(&format!("Hidden ports: {:?}", hidden)));
    } else {
        send(tx, Finding::new(Severity::Safe, MODULE, "Port Integrity",
            &format!("ss vs /proc/net/tcp consistent — no hidden ports ({} listening)", proc_listening.len())));
    }
}

fn deep_listening_scan(tx: &Sender) {
    progress(tx, "Deep scanning listening ports...");

    let suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 12345,
        4443, 3389, 5900, 5901, 6667, 6697, 1234, 4321, 2222, 3333, 9001, 9050, 9150];

    if let Ok(output) = Command::new("ss").args(["-tlnpH"]).output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut listen_count = 0;

        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            listen_count += 1;

            let addr = parts[3];
            if let Some(colon) = addr.rfind(':') {
                if let Ok(port) = addr[colon+1..].parse::<u16>() {
                    let proc_info = if parts.len() >= 6 { parts[5..].join(" ") } else { "unknown".to_string() };

                    if suspicious_ports.contains(&port) {
                        send(tx, Finding::new(Severity::Warning, MODULE, "Suspicious Port",
                            &format!("Listening on suspicious port: {}", port))
                            .with_detail(&format!("Address: {}\nProcess: {}", addr, proc_info)));
                    }
                }
            }
        }

        send(tx, Finding::new(Severity::Info, MODULE, "Listening",
            &format!("{} listening ports found", listen_count)));
    }
}

fn outbound_analysis(tx: &Sender) {
    progress(tx, "Analyzing outbound connections...");

    let conns = parse_proc_net_tcp();
    let established: Vec<&RawConnection> = conns.iter()
        .filter(|c| c.state == 1 && c.remote_ip != "127.0.0.1" && c.remote_ip != "0.0.0.0")
        .collect();

    // Build inode-to-process map
    let mut inode_map: HashMap<u64, (u32, String)> = HashMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            if let Ok(pid) = pid_str.parse::<u32>() {
                let fd_dir = format!("/proc/{}/fd", pid);
                if let Ok(fds) = fs::read_dir(&fd_dir) {
                    for fd in fds.flatten() {
                        if let Ok(link) = fs::read_link(fd.path()) {
                            let link_str = link.to_string_lossy().to_string();
                            if link_str.starts_with("socket:[") {
                                if let Some(inode_str) = link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']')) {
                                    if let Ok(inode) = inode_str.parse::<u64>() {
                                        let name = fs::read_to_string(format!("/proc/{}/comm", pid))
                                            .unwrap_or_default().trim().to_string();
                                        inode_map.insert(inode, (pid, name));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let non_standard = [4444, 5555, 6666, 7777, 1337, 31337, 12345, 6667, 6697, 9001];

    for conn in &established {
        let proc_info = inode_map.get(&conn.inode)
            .map(|(pid, name)| format!("{} (PID {})", name, pid))
            .unwrap_or_else(|| "unknown".to_string());

        if non_standard.contains(&conn.remote_port) {
            send(tx, Finding::new(Severity::Warning, MODULE, "Suspicious Outbound",
                &format!("Connection to {}:{} (suspicious port)", conn.remote_ip, conn.remote_port))
                .with_detail(&format!("Process: {}", proc_info)));
        }
    }

    send(tx, Finding::new(Severity::Info, MODULE, "Outbound",
        &format!("{} established outbound connections", established.len())));
}

fn is_virtual_bridge_member(iface: &str) -> bool {
    // Behavior-based: check if interface is a bridge member or virtual device
    // No name whitelisting — works for any container runtime, VM, or overlay

    // 1. Has a bridge master? → it's a bridge port (Docker, podman, LXC, etc.)
    let master_path = format!("/sys/class/net/{}/master", iface);
    if std::path::Path::new(&master_path).exists() {
        return true;
    }

    // 2. Is itself a bridge? (brctl, docker network)
    let bridge_path = format!("/sys/class/net/{}/bridge", iface);
    if std::path::Path::new(&bridge_path).exists() {
        return true;
    }

    // 3. Is a virtual device? (tun/tap/veth — type tells us)
    let type_path = format!("/sys/class/net/{}/type", iface);
    if let Ok(type_str) = fs::read_to_string(&type_path) {
        let net_type = type_str.trim().parse::<u32>().unwrap_or(0);
        // Type 65534 = "none" (tun/veth in a netns)
        if net_type == 65534 {
            return true;
        }
    }

    // 4. No carrier and in a network namespace (loopback-like virtual)
    let operstate = format!("/sys/class/net/{}/operstate", iface);
    let iflink = format!("/sys/class/net/{}/iflink", iface);
    let ifindex = format!("/sys/class/net/{}/ifindex", iface);
    if let (Ok(link), Ok(index)) = (fs::read_to_string(&iflink), fs::read_to_string(&ifindex)) {
        // veth pairs: iflink != ifindex (peer is in another namespace)
        if link.trim() != index.trim() {
            return true;
        }
    }
    let _ = operstate; // suppress warning

    false
}

fn promiscuous_check(tx: &Sender) {
    progress(tx, "Checking for promiscuous network interfaces...");

    if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        for line in content.lines().skip(2) {
            if let Some(iface) = line.split(':').next() {
                let iface = iface.trim();

                // Skip loopback
                if iface == "lo" {
                    continue;
                }

                let flags_path = format!("/sys/class/net/{}/flags", iface);
                if let Ok(flags_str) = fs::read_to_string(&flags_path) {
                    if let Ok(flags) = u32::from_str_radix(flags_str.trim().trim_start_matches("0x"), 16) {
                        // IFF_PROMISC = 0x100
                        if flags & 0x100 != 0 {
                            // Behavior check: is this a virtual/bridge interface?
                            if is_virtual_bridge_member(iface) {
                                // Virtual interfaces in promisc = normal, skip
                                continue;
                            }
                            send(tx, Finding::new(Severity::Warning, MODULE, "Promiscuous",
                                &format!("Physical interface '{}' is in promiscuous mode — possible sniffer", iface)));
                        }
                    }
                }
            }
        }
    }
}

fn raw_socket_check(tx: &Sender) {
    progress(tx, "Checking for raw sockets...");

    for (path, proto) in &[("/proc/net/raw", "IPv4"), ("/proc/net/raw6", "IPv6")] {
        if let Ok(content) = fs::read_to_string(path) {
            let mut suspicious_count = 0;
            for line in content.lines().skip(1) {
                if line.trim().is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 {
                    continue;
                }
                // Parse protocol number from local_address port field
                let local = parts[1];
                if let Some(colon) = local.rfind(':') {
                    let port_hex = &local[colon+1..];
                    let protocol = u16::from_str_radix(port_hex, 16).unwrap_or(0);
                    // ICMPv4=1, ICMPv6=58 are normal system sockets — skip
                    if protocol == 1 || protocol == 58 {
                        continue;
                    }
                }
                suspicious_count += 1;
            }
            if suspicious_count > 0 {
                send(tx, Finding::new(Severity::Warning, MODULE, "Raw Socket",
                    &format!("{} non-ICMP {} raw socket(s) — possible sniffer/backdoor", suspicious_count, proto)));
            }
        }
    }
}

fn ssh_authorized_keys(tx: &Sender) {
    progress(tx, "Checking SSH authorized_keys...");

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    let path = format!("{}/.ssh/authorized_keys", home);
    if let Ok(content) = fs::read_to_string(&path) {
        let keys: Vec<&str> = content.lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .collect();

        if keys.is_empty() {
            return;
        }

        send(tx, Finding::new(Severity::Info, MODULE, "SSH Keys",
            &format!("{} authorized SSH key(s)", keys.len())));

        for key in &keys {
            if key.contains("command=") {
                send(tx, Finding::new(Severity::Warning, MODULE, "SSH Forced Cmd",
                    "authorized_keys entry with forced command")
                    .with_detail(&truncate(key, 150)));
            }
            if key.contains("no-pty") && key.contains("command=") {
                send(tx, Finding::new(Severity::Warning, MODULE, "SSH Tunnel Key",
                    "Key configured for tunneling only (no-pty + command)")
                    .with_detail(&truncate(key, 150)));
            }
        }
    }
}

fn threat_feed_check(tx: &Sender) {
    progress(tx, "Matching connections against C2 threat feed...");

    let mut threat_ips = std::collections::HashSet::new();
    let feed_paths = [
        "threat_feeds/c2_ips.txt",
        "/usr/share/narayanastra/c2_ips.txt",
    ];

    let exe_dir = std::env::current_exe().ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()));

    let mut all_paths: Vec<std::path::PathBuf> = feed_paths.iter().map(std::path::PathBuf::from).collect();
    if let Some(ref dir) = exe_dir {
        all_paths.push(dir.join("../threat_feeds/c2_ips.txt"));
    }

    for path in &all_paths {
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    threat_ips.insert(trimmed.to_string());
                }
            }
            break;
        }
    }

    if threat_ips.is_empty() {
        send(tx, Finding::new(Severity::Info, MODULE, "Threat Feed",
            "No threat feed loaded — skipping IP matching"));
        return;
    }

    send(tx, Finding::new(Severity::Info, MODULE, "Threat Feed",
        &format!("Loaded {} known C2 IPs", threat_ips.len())));

    let conns = parse_proc_net_tcp();
    let mut matched = 0;
    for conn in &conns {
        if threat_ips.contains(&conn.remote_ip) {
            matched += 1;
            send(tx, Finding::new(Severity::Danger, MODULE, "C2 Match",
                &format!("Connection to known C2: {}:{}", conn.remote_ip, conn.remote_port))
                .with_detail(&format!("Local port: {}, State: {}", conn.local_port, conn.state)));
        }
    }

    if matched == 0 {
        send(tx, Finding::new(Severity::Safe, MODULE, "C2 Check",
            &format!("No connections to known C2 IPs ({} checked)", conns.len())));
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max]) } else { s.to_string() }
}

pub fn scan(tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    ss_vs_proc_compare(&tx);
    deep_listening_scan(&tx);
    outbound_analysis(&tx);
    promiscuous_check(&tx);
    raw_socket_check(&tx);
    ssh_authorized_keys(&tx);
    threat_feed_check(&tx);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
