use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::fs;
use std::time::Instant;

const MODULE: &str = "MEMORY";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn process_has_jit_library(pid: &str, maps_content: &str) -> bool {
    // Detect JIT engines by their loaded .so libraries — works for ANY app
    let jit_libraries = [
        // V8 (Chrome, Node, Electron, Deno, any Electron app)
        "libv8", "v8_context_snapshot",
        // SpiderMonkey (Firefox, gjs/GNOME apps)
        "libmozjs", "libgjs",
        // JavaScriptCore (WebKit, Safari, Epiphany)
        "libjavascriptcore", "libwebkit",
        // Java/JVM
        "libjvm", "libjava", "libjli",
        // .NET/Mono
        "libcoreclr", "libmono",
        // LuaJIT
        "libluajit",
        // QEMU/emulators
        "libtcg",
        // WASM runtimes
        "libwasmtime", "libwasmer",
        // Python JIT (3.13+)
        "libpython",
        // PCRE JIT
        "libpcre2-8",
    ];

    for line in maps_content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let mapping = parts[5].to_lowercase();
        for lib in &jit_libraries {
            if mapping.contains(lib) {
                return true;
            }
        }
    }

    // Check for statically linked JIT engines (Electron, Go, static Node)
    // These embed V8/etc inside the binary — no .so file to find
    if let Ok(exe_path) = fs::read_link(format!("/proc/{}/exe", pid)) {
        // Read first 64KB of the binary and look for JIT engine symbols
        if let Ok(data) = fs::read(&exe_path) {
            let check_size = std::cmp::min(data.len(), 2 * 1024 * 1024); // Check first 2MB
            let slice = &data[..check_size];
            let jit_symbols = [
                b"v8::Isolate" as &[u8],
                b"V8_Fatal",
                b"libv8",
                b"SpiderMonkey",
                b"JavaScriptCore",
                b"_ZN2v8",   // V8 C++ mangled symbols
                b"_ZN3JSC",  // JavaScriptCore mangled
            ];
            for sym in &jit_symbols {
                if slice.windows(sym.len()).any(|w| w == *sym) {
                    return true;
                }
            }
        }
    }

    false
}

fn rwx_anonymous_maps(tx: &Sender) {
    progress(tx, "Scanning for RWX anonymous memory mappings (code injection)...");

    let mut suspicious_pids = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            if pid_str.parse::<u32>().is_err() {
                continue;
            }

            let maps_path = format!("/proc/{}/maps", pid_str);
            let maps = match fs::read_to_string(&maps_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            let mut rwx_anon_count = 0;
            let mut rwx_anon_size: u64 = 0;

            for line in maps.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 5 {
                    continue;
                }

                let perms = parts[1];
                // rwxp = read+write+execute+private — anonymous with execute is suspicious
                if perms == "rwxp" {
                    let mapping_name = if parts.len() >= 6 { parts[5] } else { "" };
                    // Anonymous = no file backing
                    if mapping_name.is_empty() || mapping_name == "[heap]" {
                        rwx_anon_count += 1;

                        // Parse address range for size
                        let addrs: Vec<&str> = parts[0].split('-').collect();
                        if addrs.len() == 2 {
                            let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
                            let end = u64::from_str_radix(addrs[1], 16).unwrap_or(0);
                            rwx_anon_size += end - start;
                        }
                    }
                }
            }

            if rwx_anon_count > 0 {
                let name = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                    .unwrap_or_default().trim().to_string();

                // Behavior-based JIT detection: check if process has loaded any
                // JIT engine library — no hardcoded app names needed
                let has_jit = process_has_jit_library(&pid_str, &maps);

                if has_jit {
                    if rwx_anon_size > 100 * 1024 * 1024 {
                        send(tx, Finding::new(Severity::Info, MODULE, "RWX Memory",
                            &format!("PID {} ({}) — large JIT RWX: {:.1}MB ({} regions)",
                                pid_str, name, rwx_anon_size as f64 / 1048576.0, rwx_anon_count)));
                    }
                } else {
                    suspicious_pids.push(pid_str.clone());
                    send(tx, Finding::new(Severity::Warning, MODULE, "Code Injection",
                        &format!("PID {} ({}) — RWX anonymous memory: {:.1}KB ({} regions)",
                            pid_str, name, rwx_anon_size as f64 / 1024.0, rwx_anon_count))
                        .with_detail("Process has no JIT library loaded but has executable anonymous memory"));
                }
            }
        }
    }

    if suspicious_pids.is_empty() {
        send(tx, Finding::new(Severity::Safe, MODULE, "RWX Check",
            "No suspicious RWX anonymous mappings in non-JIT processes"));
    }
}

fn injected_libraries(tx: &Sender) {
    progress(tx, "Checking for injected shared libraries...");

    let suspicious_lib_patterns = [
        "/tmp/", "/dev/shm/", "/var/tmp/", "/.hidden",
        "/root/.", "/home/.", "libcrypt_mine",
    ];

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            if pid_str.parse::<u32>().is_err() {
                continue;
            }

            let maps_path = format!("/proc/{}/maps", pid_str);
            let maps = match fs::read_to_string(&maps_path) {
                Ok(m) => m,
                Err(_) => continue,
            };

            for line in maps.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    continue;
                }

                let mapping = parts[5];
                if !mapping.ends_with(".so") && !mapping.contains(".so.") {
                    continue;
                }

                for pattern in &suspicious_lib_patterns {
                    if mapping.contains(pattern) {
                        let name = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                            .unwrap_or_default().trim().to_string();
                        send(tx, Finding::new(Severity::Danger, MODULE, "Injected Library",
                            &format!("PID {} ({}) loaded suspicious library: {}", pid_str, name, mapping))
                            .with_detail("Library loaded from temp/hidden directory — likely injected"));
                        break;
                    }
                }

                // Check for deleted libraries still mapped
                if mapping.contains("(deleted)") && !mapping.contains("/usr/") {
                    let name = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                        .unwrap_or_default().trim().to_string();
                    send(tx, Finding::new(Severity::Warning, MODULE, "Deleted Library",
                        &format!("PID {} ({}) has deleted library mapped: {}", pid_str, name, mapping)));
                }
            }
        }
    }
}

fn devshm_analysis(tx: &Sender) {
    progress(tx, "Analyzing /dev/shm contents...");

    if let Ok(entries) = fs::read_dir("/dev/shm") {
        let mut count = 0;
        for entry in entries.flatten() {
            count += 1;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if let Ok(meta) = path.metadata() {
                let size = meta.len();

                // Large files in /dev/shm
                if size > 10_000_000 {
                    send(tx, Finding::new(Severity::Info, MODULE, "/dev/shm",
                        &format!("Large file in /dev/shm: {} ({:.1}MB)", name, size as f64 / 1048576.0)));
                }

                // Check magic bytes for executables
                if path.is_file() {
                    if let Ok(data) = fs::read(&path) {
                        if data.len() >= 4 {
                            if &data[..4] == b"\x7fELF" {
                                send(tx, Finding::new(Severity::Danger, MODULE, "/dev/shm ELF",
                                    &format!("ELF binary in shared memory: {}", name))
                                    .with_detail(&format!("Size: {} bytes — likely malware staging", size)));
                            }
                            if data.len() >= 2 && &data[..2] == b"MZ" {
                                send(tx, Finding::new(Severity::Danger, MODULE, "/dev/shm PE",
                                    &format!("PE executable in shared memory: {}", name)));
                            }
                            // Shellcode-like patterns
                            if data.len() > 32 {
                                let nop_sled = data.windows(16).any(|w| w.iter().all(|&b| b == 0x90));
                                if nop_sled {
                                    send(tx, Finding::new(Severity::Danger, MODULE, "Shellcode",
                                        &format!("Possible shellcode (NOP sled) in /dev/shm: {}", name)));
                                }
                            }
                        }
                    }
                }
            }
        }

        if count == 0 {
            send(tx, Finding::new(Severity::Safe, MODULE, "/dev/shm",
                "/dev/shm is empty"));
        }
    }
}

fn process_hollowing(tx: &Sender) {
    progress(tx, "Checking for process hollowing indicators...");

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid_str = entry.file_name().to_string_lossy().to_string();
            if pid_str.parse::<u32>().is_err() {
                continue;
            }

            // Compare /proc/PID/exe target with /proc/PID/cmdline[0]
            let exe = match fs::read_link(format!("/proc/{}/exe", pid_str)) {
                Ok(e) => e.to_string_lossy().to_string(),
                Err(_) => continue,
            };

            let cmdline = match fs::read_to_string(format!("/proc/{}/cmdline", pid_str)) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let cmd_first = cmdline.split('\0').next().unwrap_or("").to_string();

            if exe.contains("(deleted)") {
                continue; // Already caught by rootkit module
            }

            // If exe and cmdline[0] point to completely different binaries
            if !cmd_first.is_empty() && !exe.is_empty() {
                let exe_base = exe.rsplit('/').next().unwrap_or(&exe);
                let cmd_base = cmd_first.rsplit('/').next().unwrap_or(&cmd_first);

                // Some processes legitimately have different names (busybox, python scripts)
                let legit_mismatches = ["python", "python3", "ruby", "perl", "node", "java",
                    "bash", "sh", "zsh", "busybox", "env", "sudo", "su", "dbus"];

                if exe_base != cmd_base
                    && !legit_mismatches.iter().any(|l| exe_base.contains(l) || cmd_base.contains(l))
                    && !cmd_first.starts_with('-') // login shells
                {
                    let name = fs::read_to_string(format!("/proc/{}/comm", pid_str))
                        .unwrap_or_default().trim().to_string();
                    send(tx, Finding::new(Severity::Info, MODULE, "Name Mismatch",
                        &format!("PID {} — exe='{}' but cmdline='{}'", pid_str, exe_base, cmd_base))
                        .with_detail(&format!("Process: {}\nFull exe: {}\nFull cmd: {}", name, exe, cmd_first)));
                }
            }
        }
    }
}

pub fn scan(tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    rwx_anonymous_maps(&tx);
    injected_libraries(&tx);
    devshm_analysis(&tx);
    process_hollowing(&tx);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
