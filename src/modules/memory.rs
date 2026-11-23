use crate::config::ScanConfig;
use crate::procfs::{self, MapEntry};
use crate::report::{progress as prog, send, Finding, ScanEvent, Sender, Severity};
use crate::util;
use std::io::Read;
use std::time::Instant;

const MODULE: &str = "MEMORY";

fn progress(tx: &Sender, msg: &str) {
    prog(tx, MODULE, msg)
}

/// Libraries that really contain a JIT. libpcre2-8 and libpython were removed: almost
/// every daemon loads libpcre2-8 (via libselinux), which silently whitelisted sshd and
/// systemd from injection detection.
const JIT_LIBS: [&str; 15] = [
    "libv8",
    "v8_context_snapshot",
    "libnode",
    "libmozjs",
    "libxul.so",
    "libjavascriptcoregtk",
    "libwebkit2gtk",
    "libjvm",
    "libcoreclr",
    "libclrjit",
    "libmonosgen",
    "libluajit",
    "libwasmtime",
    "libwasmer",
    "libqemu",
];

/// Common daemons that never JIT — RWX memory there is a strong injection signal.
const NON_JIT_DAEMONS: [&str; 16] = [
    "sshd",
    "sshd-session",
    "systemd",
    "cron",
    "crond",
    "bash",
    "sh",
    "dash",
    "dbus-daemon",
    "rsyslogd",
    "systemd-journal",
    "systemd-logind",
    "nginx",
    "apache2",
    "httpd",
    "sudo",
];

fn has_jit_engine(pid: u32, maps: &[MapEntry]) -> bool {
    if maps.iter().any(|m| {
        let file = m.path.rsplit('/').next().unwrap_or("").to_lowercase();
        JIT_LIBS.iter().any(|j| file.starts_with(j))
    }) {
        return true;
    }
    // statically linked engines (Electron, node): scan at most 2MB of the binary
    let (exe, deleted) = procfs::exe(pid);
    if exe.is_empty() || deleted {
        return false;
    }
    let mut buf = Vec::with_capacity(2 * 1024 * 1024);
    match std::fs::File::open(&exe) {
        Ok(f) => {
            if f.take(2 * 1024 * 1024).read_to_end(&mut buf).is_err() {
                return false;
            }
        }
        Err(_) => return false,
    }
    let needles: [&[u8]; 4] = [b"_ZN2v88internal", b"V8_Fatal", b"_ZN3JSC", b"SpiderMonkey"];
    needles.iter().any(|n| buf.windows(n.len()).any(|w| w == *n))
}

fn injection_scan(tx: &Sender) {
    progress(tx, "Scanning memory maps for injected code (RWX, anon exec, memfd, temp libs)...");
    let mut flagged = 0usize;
    for pid in util::proc_pids() {
        if pid == std::process::id() {
            continue;
        }
        let maps = match procfs::maps(pid) {
            Some(m) if !m.is_empty() => m,
            _ => continue,
        };
        let name = procfs::comm(pid);
        let rwx: Vec<&MapEntry> = maps.iter().filter(|m| m.is_write() && m.is_exec() && (m.is_anon() || m.path == "[heap]" || m.path == "[stack]")).collect();
        let anon_rx: Vec<&MapEntry> = maps.iter().filter(|m| m.is_exec() && !m.is_write() && m.is_anon()).collect();
        let memfd: Vec<&MapEntry> = maps.iter().filter(|m| m.is_exec() && m.path.starts_with("/memfd:")).collect();
        // hidden dirs under /home are normal (~/.vscode-server, ~/.cargo, ~/.conda); a hidden
        // dir under /usr, /lib, /etc, /var is not
        let in_home = |p: &str| p.starts_with("/home/") || p.starts_with("/root/");
        let temp_libs: Vec<&MapEntry> = maps
            .iter()
            .filter(|m| {
                m.is_exec()
                    && !m.path.starts_with("/tmp/.mount_")
                    && (util::is_temp_path(&m.path) || (util::has_hidden_component(&m.path) && !in_home(&m.path) && !m.path.starts_with("/memfd:")))
            })
            .collect();
        let deleted_libs: Vec<&MapEntry> = maps
            .iter()
            .filter(|m| m.is_exec() && m.deleted && !m.path.starts_with("/memfd:") && !m.path.starts_with("/usr/") && !m.path.starts_with("/lib"))
            .collect();

        let (exe_path, _) = procfs::exe(pid);
        for m in memfd.iter().filter(|m| m.path != exe_path) {
            flagged += 1;
            send(
                tx,
                Finding::new(Severity::Danger, MODULE, "Fileless", &format!("PID {} ({}) has executable memfd mapping {}", pid, name, m.path))
                    .with_detail("Code loaded from an anonymous memory file — fileless malware technique")
                    .subject(&format!("pid:{}:memfd:{}", pid, m.path)),
            );
        }
        let needs_jit = !temp_libs.is_empty() || !rwx.is_empty() || !anon_rx.is_empty();
        let jit = needs_jit && has_jit_engine(pid, &maps);
        for m in &temp_libs {
            flagged += 1;
            // JVMs legitimately unpack native libs to /tmp (JNA, Netty, sqlite-jdbc)
            send(
                tx,
                Finding::new(
                    if jit { Severity::Warning } else { Severity::Danger },
                    MODULE,
                    "Injected Library",
                    &format!("PID {} ({}) maps executable code from {}", pid, name, m.path),
                )
                .with_detail(if m.deleted { "Library loaded from a temp/hidden path and then deleted" } else { "Library loaded from a temp/hidden path" })
                .subject(&format!("pid:{}:lib:{}", pid, m.path))
                .artifact(&m.path),
            );
        }
        for m in &deleted_libs {
            flagged += 1;
            send(
                tx,
                Finding::new(Severity::Warning, MODULE, "Deleted Library", &format!("PID {} ({}) runs code from deleted file {}", pid, name, m.path))
                    .subject(&format!("pid:{}:del:{}", pid, m.path)),
            );
        }

        if rwx.is_empty() && anon_rx.is_empty() {
            continue;
        }
        let daemon = NON_JIT_DAEMONS.contains(&name.as_str());
        let rwx_size: u64 = rwx.iter().map(|m| m.size()).sum();
        if !rwx.is_empty() {
            if jit && !daemon {
                if rwx_size > 512 * 1024 * 1024 {
                    send(
                        tx,
                        Finding::new(
                            Severity::Info,
                            MODULE,
                            "RWX Memory",
                            &format!("PID {} ({}) JIT engine with {:.0}MB RWX", pid, name, rwx_size as f64 / 1048576.0),
                        )
                        .subject(&format!("pid:{}:jit", pid)),
                    );
                }
            } else {
                flagged += 1;
                send(
                    tx,
                    Finding::new(
                        if daemon { Severity::Danger } else { Severity::Warning },
                        MODULE,
                        "Code Injection",
                        &format!("PID {} ({}) — {} RWX region(s), {:.1}KB, no JIT engine", pid, name, rwx.len(), rwx_size as f64 / 1024.0),
                    )
                    .with_detail(&format!(
                        "First region: {:x}-{:x} {} {}",
                        rwx[0].start,
                        rwx[0].end,
                        rwx[0].perms,
                        if rwx[0].path.is_empty() { "[anon]" } else { &rwx[0].path }
                    ))
                    .subject(&format!("pid:{}:rwx", pid)),
                );
            }
        }
        // anonymous r-x is normal for JITs and libffi trampolines; only flag in daemons
        if !anon_rx.is_empty() && daemon && !jit {
            flagged += 1;
            send(
                tx,
                Finding::new(
                    Severity::Warning,
                    MODULE,
                    "Code Injection",
                    &format!("PID {} ({}) has {} anonymous executable region(s)", pid, name, anon_rx.len()),
                )
                .with_detail("Shellcode is often mapped RW, written, then mprotect'ed to RX")
                .subject(&format!("pid:{}:anonrx", pid)),
            );
        }
    }
    if flagged == 0 {
        send(tx, Finding::new(Severity::Safe, MODULE, "Memory Check", "No injected or fileless code found in process memory maps").subject("mem"));
    }
}

fn process_hollowing(tx: &Sender) {
    progress(tx, "Checking exe vs argv[0] mismatches (hollowing / masquerading)...");
    let interpreters = ["python", "ruby", "perl", "node", "java", "bash", "sh", "zsh", "dash", "busybox", "env", "sudo", "su", "php", "lua", "electron"];
    for pid in util::proc_pids() {
        let (exe, deleted) = procfs::exe(pid);
        if exe.is_empty() || deleted {
            continue;
        }
        let argv0 = procfs::read_cmdline_argv0(pid);
        if argv0.is_empty() || argv0.starts_with('-') || argv0.starts_with('[') {
            continue;
        }
        let exe_base = exe.rsplit('/').next().unwrap_or(&exe);
        let cmd_base = argv0.split_whitespace().next().unwrap_or("").rsplit('/').next().unwrap_or("");
        if cmd_base.is_empty() || exe_base == cmd_base || exe_base.starts_with(cmd_base) || cmd_base.starts_with(exe_base) {
            continue;
        }
        if interpreters.iter().any(|l| exe_base.contains(l) || cmd_base.contains(l)) {
            continue;
        }
        send(
            tx,
            Finding::new(Severity::Info, MODULE, "Name Mismatch", &format!("PID {} — exe '{}' but argv[0] '{}'", pid, exe_base, cmd_base))
                .with_detail(&format!("Full exe: {}\nargv[0]: {}", exe, argv0))
                .subject(&format!("pid:{}", pid)),
        );
    }
}

pub fn scan(_cfg: &ScanConfig, tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));
    injection_scan(&tx);
    process_hollowing(&tx);
    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
