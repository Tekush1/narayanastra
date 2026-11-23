//! Socket enumeration from two independent kernel views:
//!
//! 1. /proc/net/{tcp,tcp6,udp,udp6} (seq_file — what tcp4_seq_show hooks hide from)
//! 2. NETLINK_SOCK_DIAG (inet_diag) (what `ss` uses — a different code path)
//!
//! plus a bind() probe that asks the kernel directly whether a port is taken.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
}

impl std::fmt::Display for Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
            }
        )
    }
}

pub const TCP_ESTABLISHED: u8 = 1;
pub const TCP_CLOSE: u8 = 7;
pub const TCP_LISTEN: u8 = 10;

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Conn {
    pub proto: Proto,
    pub v6: bool,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

impl Conn {
    /// A socket that accepts traffic: TCP LISTEN, or a bound-but-unconnected UDP socket.
    pub fn is_listener(&self) -> bool {
        match self.proto {
            Proto::Tcp => self.state == TCP_LISTEN,
            Proto::Udp => self.state == TCP_CLOSE && self.lport != 0 && self.remote.is_unspecified(),
        }
    }
    pub fn key(&self) -> (Proto, u16) {
        (self.proto, self.lport)
    }
}

/// IPv4-mapped IPv6 (::ffff:a.b.c.d) becomes plain IPv4 so threat-feed matching works.
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

pub fn parse_hex_ip(hex: &str) -> Option<IpAddr> {
    match hex.len() {
        8 => {
            let w = u32::from_str_radix(hex, 16).ok()?;
            let b = w.to_le_bytes();
            Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        32 => {
            let mut bytes = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16).ok()?;
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            Some(normalize(IpAddr::V6(Ipv6Addr::from(bytes))))
        }
        _ => None,
    }
}

fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    let (a, p) = s.rsplit_once(':')?;
    Some((parse_hex_ip(a)?, u16::from_str_radix(p, 16).ok()?))
}

pub fn parse_proc_net(content: &str, proto: Proto, v6: bool) -> Vec<Conn> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 {
            continue;
        }
        let (local, lport) = match parse_addr_port(f[1]) {
            Some(x) => x,
            None => continue,
        };
        let (remote, rport) = match parse_addr_port(f[2]) {
            Some(x) => x,
            None => continue,
        };
        out.push(Conn {
            proto,
            v6,
            local,
            lport,
            remote,
            rport,
            state: u8::from_str_radix(f[3], 16).unwrap_or(0),
            uid: f[7].parse().unwrap_or(0),
            inode: f[9].parse().unwrap_or(0),
        });
    }
    out
}

pub fn proc_net_all() -> Vec<Conn> {
    let mut v = Vec::new();
    for (path, proto, v6) in
        [("/proc/net/tcp", Proto::Tcp, false), ("/proc/net/tcp6", Proto::Tcp, true), ("/proc/net/udp", Proto::Udp, false), ("/proc/net/udp6", Proto::Udp, true)]
    {
        if let Some(c) = crate::util::read_proc(path) {
            v.extend(parse_proc_net(&c, proto, v6));
        }
    }
    v
}

// ───────────────────────── netlink sock_diag ─────────────────────────

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

fn netlink_dump(family: u8, protocol: u8) -> Option<Vec<Conn>> {
    unsafe {
        let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
        if fd < 0 {
            return None;
        }
        // receive timeout so a broken kernel can't hang us
        let tv = libc::timeval { tv_sec: 3, tv_usec: 0 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const libc::c_void, std::mem::size_of::<libc::timeval>() as u32);

        // nlmsghdr (16) + inet_diag_req_v2 (56)
        let mut req = [0u8; 72];
        req[0..4].copy_from_slice(&72u32.to_ne_bytes());
        req[4..6].copy_from_slice(&SOCK_DIAG_BY_FAMILY.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        req[16] = family;
        req[17] = protocol;
        req[20..24].copy_from_slice(&0xffff_ffffu32.to_ne_bytes()); // all states

        let mut sa: libc::sockaddr_nl = std::mem::zeroed();
        sa.nl_family = libc::AF_NETLINK as u16;
        let sent = libc::sendto(
            fd,
            req.as_ptr() as *const libc::c_void,
            req.len(),
            0,
            &sa as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        );
        if sent < 0 {
            libc::close(fd);
            return None;
        }

        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        let proto = if protocol as i32 == libc::IPPROTO_UDP { Proto::Udp } else { Proto::Tcp };
        'outer: loop {
            let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
            if n <= 0 {
                libc::close(fd);
                return if out.is_empty() { None } else { Some(out) };
            }
            let n = n as usize;
            let mut off = 0usize;
            while off + 16 <= n {
                let len = u32::from_ne_bytes(buf[off..off + 4].try_into().ok()?) as usize;
                let typ = u16::from_ne_bytes(buf[off + 4..off + 6].try_into().ok()?);
                if len < 16 || off + len > n {
                    break;
                }
                if typ == NLMSG_DONE {
                    break 'outer;
                }
                if typ == NLMSG_ERROR {
                    libc::close(fd);
                    return None;
                }
                let m = &buf[off + 16..off + len];
                if m.len() >= 72 {
                    out.push(parse_diag_msg(m, proto));
                }
                off += (len + 3) & !3;
            }
        }
        libc::close(fd);
        Some(out)
    }
}

fn parse_diag_msg(m: &[u8], proto: Proto) -> Conn {
    let family = m[0];
    let state = m[1];
    let sport = u16::from_be_bytes([m[4], m[5]]);
    let dport = u16::from_be_bytes([m[6], m[7]]);
    let (local, remote, v6) = if family as i32 == libc::AF_INET6 {
        let mut s = [0u8; 16];
        let mut d = [0u8; 16];
        s.copy_from_slice(&m[8..24]);
        d.copy_from_slice(&m[24..40]);
        (normalize(IpAddr::V6(Ipv6Addr::from(s))), normalize(IpAddr::V6(Ipv6Addr::from(d))), true)
    } else {
        (IpAddr::V4(Ipv4Addr::new(m[8], m[9], m[10], m[11])), IpAddr::V4(Ipv4Addr::new(m[24], m[25], m[26], m[27])), false)
    };
    let uid = u32::from_ne_bytes([m[64], m[65], m[66], m[67]]);
    let inode = u32::from_ne_bytes([m[68], m[69], m[70], m[71]]) as u64;
    Conn { proto, v6, local, lport: sport, remote, rport: dport, state, uid, inode }
}

/// All sockets via netlink. None if netlink sock_diag is unavailable.
pub fn netlink_all() -> Option<Vec<Conn>> {
    let mut all = Vec::new();
    let mut any = false;
    for fam in [libc::AF_INET as u8, libc::AF_INET6 as u8] {
        for proto in [libc::IPPROTO_TCP as u8, libc::IPPROTO_UDP as u8] {
            if let Some(v) = netlink_dump(fam, proto) {
                any = true;
                all.extend(v);
            }
        }
    }
    if any {
        Some(all)
    } else {
        None
    }
}

// ───────────────────────── bind probe ─────────────────────────

/// true if the kernel refuses to bind the port (EADDRINUSE) — i.e. something owns it.
pub fn port_in_use(proto: Proto, v6: bool, port: u16) -> bool {
    unsafe {
        let family = if v6 { libc::AF_INET6 } else { libc::AF_INET };
        let ty = match proto {
            Proto::Tcp => libc::SOCK_STREAM,
            Proto::Udp => libc::SOCK_DGRAM,
        };
        let fd = libc::socket(family, ty | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return false;
        }
        let one: libc::c_int = 1;
        if proto == Proto::Tcp {
            // ignore TIME_WAIT leftovers, still conflicts with real listeners
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &one as *const _ as *const libc::c_void, 4);
        }
        let rc = if v6 {
            libc::setsockopt(fd, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, &one as *const _ as *const libc::c_void, 4);
            let mut sa: libc::sockaddr_in6 = std::mem::zeroed();
            sa.sin6_family = libc::AF_INET6 as u16;
            sa.sin6_port = port.to_be();
            libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in6>() as u32)
        } else {
            let mut sa: libc::sockaddr_in = std::mem::zeroed();
            sa.sin_family = libc::AF_INET as u16;
            sa.sin_port = port.to_be();
            libc::bind(fd, &sa as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_in>() as u32)
        };
        let in_use = rc != 0 && *libc::__errno_location() == libc::EADDRINUSE;
        libc::close(fd);
        in_use
    }
}

// ───────────────────────── threat feed ─────────────────────────

#[derive(Clone, Debug)]
pub enum FeedEntry {
    Ip(IpAddr),
    Cidr(IpAddr, u8),
}

pub fn parse_feed(content: &str) -> Vec<FeedEntry> {
    let mut v = Vec::new();
    for line in content.lines() {
        let t = line.split('#').next().unwrap_or("").trim();
        if t.is_empty() {
            continue;
        }
        if let Some((ip, bits)) = t.split_once('/') {
            if let (Ok(ip), Ok(bits)) = (ip.parse::<IpAddr>(), bits.parse::<u8>()) {
                v.push(FeedEntry::Cidr(normalize(ip), bits));
            }
        } else if let Ok(ip) = t.parse::<IpAddr>() {
            v.push(FeedEntry::Ip(normalize(ip)));
        }
    }
    v
}

pub fn feed_matches(feed: &[FeedEntry], ip: &IpAddr) -> bool {
    let ip = normalize(*ip);
    feed.iter().any(|e| match e {
        FeedEntry::Ip(x) => *x == ip,
        FeedEntry::Cidr(net, bits) => match (net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let b = (*bits).min(32) as u32;
                let mask = if b == 0 { 0 } else { u32::MAX << (32 - b) };
                (u32::from(*n) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let b = (*bits).min(128) as u32;
                let mask = if b == 0 { 0 } else { u128::MAX << (128 - b) };
                (u128::from(*n) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        },
    })
}

pub fn is_loopback_or_unspec(ip: &IpAddr) -> bool {
    let ip = normalize(*ip);
    ip.is_loopback() || ip.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ipv4_ipv6_and_mapped() {
        assert_eq!(parse_hex_ip("0100007F").unwrap(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(parse_hex_ip("00000000000000000000000001000000").unwrap(), "::1".parse::<IpAddr>().unwrap());
        // ::ffff:10.0.0.5 in /proc/net/tcp6 format
        assert_eq!(parse_hex_ip("0000000000000000FFFF00000500000A").unwrap(), "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn proc_net_tcp6_line() {
        let c = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22222 1 0000000000000000 100 0 0 10 0\n   1: 0000000000000000FFFF00000500000A:A2C4 0000000000000000FFFF00000100A8C0:115C 01 00000000:00000000 00:00000000 00000000  1000        0 33333 1\n";
        let v = parse_proc_net(c, Proto::Tcp, true);
        assert_eq!(v.len(), 2);
        assert!(v[0].is_listener());
        assert_eq!(v[0].lport, 22);
        assert_eq!(v[1].remote, "192.168.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(v[1].rport, 4444);
        assert_eq!(v[1].uid, 1000);
    }

    #[test]
    fn feed_cidr_and_mapped() {
        let feed = parse_feed("# c2\n45.9.148.0/24\n1.2.3.4\n2001:db8::/32\nbad\n");
        assert!(feed_matches(&feed, &"45.9.148.77".parse().unwrap()));
        assert!(feed_matches(&feed, &"::ffff:1.2.3.4".parse().unwrap()));
        assert!(feed_matches(&feed, &"2001:db8::5".parse().unwrap()));
        assert!(!feed_matches(&feed, &"8.8.8.8".parse().unwrap()));
    }
}
