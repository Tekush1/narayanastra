mod modules;
mod report;

use colored::*;
use report::{Finding, ScanEvent, ScanReport, Severity};
use std::collections::HashSet;
use std::env;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

fn print_banner() {
    println!("{}", "╔══════════════════════════════════════════════════════════════════════╗".cyan());
    println!("{}", "║                                                                      ║".cyan());
    println!("{}", "║   ███╗   ██╗ █████╗ ██████╗  █████╗ ██╗   ██╗ █████╗ ███╗   ██╗    ║".cyan());
    println!("{}", "║   ████╗  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗████╗  ██║    ║".cyan());
    println!("{}", "║   ██╔██╗ ██║███████║██████╔╝███████║ ╚████╔╝ ███████║██╔██╗ ██║    ║".cyan());
    println!("{}", "║   ██║╚██╗██║██╔══██║██╔══██╗██╔══██║  ╚██╔╝  ██╔══██║██║╚██╗██║    ║".cyan());
    println!("{}", "║   ██║ ╚████║██║  ██║██║  ██║██║  ██║   ██║   ██║  ██║██║ ╚████║    ║".cyan());
    println!("{}", "║   ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝    ║".cyan());
    println!("{}", "║                                                                      ║".cyan());
    println!("{}", "║    █████╗ ███████╗████████╗██████╗  █████╗                           ║".cyan());
    println!("{}", "║   ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗                          ║".cyan());
    println!("{}", "║   ███████║███████╗   ██║   ██████╔╝███████║                          ║".cyan());
    println!("{}", "║   ██╔══██║╚════██║   ██║   ██╔══██╗██╔══██║                          ║".cyan());
    println!("{}", "║   ██║  ██║███████║   ██║   ██║  ██║██║  ██║                          ║".cyan());
    println!("{}", "║   ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝                          ║".cyan());
    println!("{}", "║                                                                      ║".cyan());
    println!("{}", "║   नारायणास्त्र — Vishnu's Ultimate Weapon                              ║".cyan());
    println!("{}", "║   v1.0.0 | Post-Compromise Deep Scanner                             ║".cyan());
    let module_label = if cfg!(target_os = "windows") { "7 Checks" } else { "7 Modules" };
    println!("{}", format!("║   {} | Multi-threaded | Real-time Output                     ║", module_label).cyan());
    println!("{}", "║                                                                      ║".cyan());
    println!("{}", "║   Built by Kushagra Dwivedi | CyberHX                               ║".cyan());
    println!("{}", "╚══════════════════════════════════════════════════════════════════════╝".cyan());
    println!();
}

#[cfg(target_os = "linux")]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "windows")]
fn is_root() -> bool {
    // On Windows, check if running as Administrator
    std::process::Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn spawn_scan_threads(root: bool, tx: mpsc::Sender<ScanEvent>) -> Vec<thread::JoinHandle<()>> {
    let tx1 = tx.clone();
    let r1 = root;
    let h1 = thread::spawn(move || modules::rootkit::scan(r1, tx1));

    let tx2 = tx.clone();
    let h2 = thread::spawn(move || modules::process::scan(tx2));

    let tx3 = tx.clone();
    let h3 = thread::spawn(move || modules::network::scan(tx3));

    let tx4 = tx.clone();
    let r4 = root;
    let h4 = thread::spawn(move || modules::files::scan(r4, tx4));

    let tx5 = tx.clone();
    let h5 = thread::spawn(move || modules::memory::scan(tx5));

    let tx6 = tx.clone();
    let r6 = root;
    let h6 = thread::spawn(move || modules::logs::scan(r6, tx6));

    let tx7 = tx.clone();
    let h7 = thread::spawn(move || modules::antiforensics::scan(tx7));

    vec![h1, h2, h3, h4, h5, h6, h7]
}

#[cfg(target_os = "windows")]
fn spawn_scan_threads(_root: bool, tx: mpsc::Sender<ScanEvent>) -> Vec<thread::JoinHandle<()>> {
    let tx1 = tx.clone();
    let h1 = thread::spawn(move || modules::windows::scan(tx1));
    vec![h1]
}

fn run_scan(root: bool, full_scan: bool, quiet: bool) -> Vec<Finding> {
    let (tx, rx) = mpsc::channel::<ScanEvent>();

    let handles = spawn_scan_threads(root, tx.clone());

    drop(tx);

    let mut findings = Vec::new();
    let mut modules_done = 0;

    for event in rx {
        match event {
            ScanEvent::ModuleStart(name) => {
                if !quiet {
                    println!("  {} {} {}",
                        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).bright_black(),
                        ">>".cyan().bold(),
                        format!("{} started", name).cyan());
                }
            }
            ScanEvent::ModuleProgress(name, msg) => {
                if !quiet {
                    println!("  {} {} {}",
                        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).bright_black(),
                        format!("[{}]", name).bright_black(),
                        msg.bright_black());
                }
            }
            ScanEvent::Finding(finding) => {
                if !quiet {
                    finding.print_live();
                }
                findings.push(finding);
            }
            ScanEvent::ModuleDone(name, duration) => {
                modules_done += 1;
                if !quiet {
                    let total_modules = if cfg!(target_os = "windows") { 1 } else { 7 };
                    println!("  {} {} {} {}\n",
                        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).bright_black(),
                        "<<".green().bold(),
                        format!("{} complete", name).green(),
                        format!("({:.2}s) [{}/{}]", duration.as_secs_f64(), modules_done, total_modules).bright_black());
                }
            }
        }
    }

    for h in handles {
        let _ = h.join();
    }

    let _ = full_scan;
    findings
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let full_scan = args.iter().any(|a| a == "--full" || a == "-f");
    let help = args.iter().any(|a| a == "--help" || a == "-h");

    // Parse --watch N
    let watch_secs: Option<u64> = args.windows(2)
        .find(|w| w[0] == "--watch" || w[0] == "-w")
        .and_then(|w| w[1].parse().ok());
    let watch_flag = args.iter().any(|a| a == "--watch" || a == "-w");
    let watch_interval = if watch_flag { Some(watch_secs.unwrap_or(30)) } else { None };

    // Parse --offline /mnt/target
    let offline_root: Option<String> = args.windows(2)
        .find(|w| w[0] == "--offline")
        .map(|w| w[1].clone());

    // Parse --remote user@host
    let remote_target: Option<String> = args.windows(2)
        .find(|w| w[0] == "--remote")
        .map(|w| w[1].clone());

    print_banner();

    if help {
        println!("  {} narayanastra [OPTIONS]\n", "Usage:".bold());
        println!("  {}          Full deep scan (needs sudo)", "--full, -f".cyan());
        println!("  {}        Watch mode — rescan every N seconds (default 30)", "--watch N".cyan());
        println!("  {} Offline scan — mounted disk (USB boot forensics)", "--offline PATH".cyan());
        println!("  {} Remote scan — SSH into server, scan, pull report", "--remote HOST".cyan());
        println!("  {}          Show this help", "--help, -h".cyan());
        println!();
        println!("  {}:", "Examples".bold());
        println!("    narayanastra                              # one-shot scan");
        println!("    narayanastra --watch 30                    # rescan every 30s");
        println!("    sudo narayanastra --full                   # full root scan");
        println!("    sudo narayanastra -f --watch 60            # full + watch every 60s");
        println!("    sudo narayanastra --offline /mnt/disk       # offline forensic scan");
        println!("    narayanastra --remote root@54.23.11.90      # remote server scan");
        println!("    narayanastra --remote ubuntu@myserver -f    # remote full scan");
        println!();
        return;
    }

    let root = is_root();

    if full_scan && !root {
        println!("{}", "  [!] Full scan requested but not running as root/sudo.".red().bold());
        println!("{}", "      Run with: sudo narayanastra --full".yellow());
        println!("{}", "      Continuing with user-level scan...\n".yellow());
    }

    let scan_mode = if offline_root.is_some() { "Offline (forensic)" }
        else if remote_target.is_some() { "Remote" }
        else if root && full_scan { "Full (root)" }
        else { "User" };

    let hostname = if cfg!(target_os = "windows") {
        env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    } else {
        std::fs::read_to_string("/etc/hostname")
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string()
    };

    let username = env::var("USER")
        .or_else(|_| env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());

    println!("  {} {}", "Scan Mode:".bold(), scan_mode.cyan());
    if let Some(ref target) = offline_root {
        println!("  {} {}", "Target:".bold(), target.cyan());
    }
    println!("  {} {}", "Hostname:".bold(), hostname.cyan());
    println!("  {} {}", "Username:".bold(), username.cyan());
    println!("  {} {}", "Platform:".bold(), std::env::consts::OS.cyan());
    println!("  {} {}", "Time:".bold(),
        chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string().cyan());

    if let Some(interval) = watch_interval {
        println!("  {} {}",
            "Watch:".bold(),
            format!("every {}s (Ctrl+C to stop)", interval).cyan());
    }
    println!();

    // ══════════════════════════════════════════
    //  REMOTE MODE
    // ══════════════════════════════════════════
    if let Some(ref remote_host) = remote_target {
        println!("  {}\n", ">> Remote scan — connecting via SSH...".bold().cyan());

        let self_path = env::current_exe().unwrap_or_default();
        let remote_path = "/tmp/narayanastra_remote";
        let remote_report = "/tmp/narayanastra_remote_report";
        let full_flag = if full_scan { " --full" } else { "" };

        // Step 1: Upload binary
        println!("  {} {}", "[1/4]".cyan().bold(), "Uploading scanner binary...".white());
        let scp_status = std::process::Command::new("scp")
            .args(["-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10",
                self_path.to_str().unwrap_or("narayanastra"), &format!("{}:{}", remote_host, remote_path)])
            .status();

        match scp_status {
            Ok(s) if s.success() => {}
            _ => {
                println!("  {} {}", "[!]".red().bold(), "Failed to upload binary via SCP.".red());
                println!("      Check: SSH key setup, hostname, network connectivity");
                println!("      Try: ssh {} 'echo ok'", remote_host);
                return;
            }
        }

        // Step 2: Run scan remotely
        println!("  {} {}", "[2/4]".cyan().bold(), format!("Running scan on {}...", remote_host).white());
        let scan_cmd = format!(
            "chmod +x {} && {}{} 2>&1; cp scan_report.json {} 2>/dev/null; cp scan_report.txt {}.txt 2>/dev/null",
            remote_path, remote_path, full_flag, remote_report, remote_report
        );

        let ssh_output = std::process::Command::new("ssh")
            .args(["-o", "ConnectTimeout=10", remote_host.as_str(), &scan_cmd])
            .output();

        match ssh_output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Print remote scan output
                for line in stdout.lines() {
                    println!("  {} {}", "[REMOTE]".bright_black(), line);
                }
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    if !stderr.is_empty() {
                        println!("  {} {}", "[REMOTE ERR]".red(), stderr.trim());
                    }
                }
            }
            Err(e) => {
                println!("  {} SSH failed: {}", "[!]".red().bold(), e);
                return;
            }
        }

        // Step 3: Pull report back
        println!("  {} {}", "[3/4]".cyan().bold(), "Downloading reports...".white());
        let local_json = format!("remote_scan_{}.json", remote_host.replace('@', "_").replace('.', "_"));
        let local_txt = format!("remote_scan_{}.txt", remote_host.replace('@', "_").replace('.', "_"));

        let _ = std::process::Command::new("scp")
            .args([&format!("{}:{}", remote_host, remote_report), &local_json])
            .status();
        let _ = std::process::Command::new("scp")
            .args([&format!("{}:{}.txt", remote_host, remote_report), &local_txt])
            .status();

        // Step 4: Cleanup remote
        println!("  {} {}", "[4/4]".cyan().bold(), "Cleaning up remote...".white());
        let _ = std::process::Command::new("ssh")
            .args([remote_host.as_str(),
                &format!("rm -f {} {} {}.txt scan_report.json scan_report.txt", remote_path, remote_report, remote_report)])
            .status();

        println!();
        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
        println!("  {} {}", "Remote scan complete.".bold().cyan(), remote_host.cyan());
        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());

        if std::path::Path::new(&local_json).exists() {
            println!("\n  {} {}", "[+] Report:".green().bold(), local_txt.white().bold());
            println!("  {} {}", "[+] JSON:".green().bold(), local_json.white().bold());
        } else {
            println!("\n  {} Reports may not have downloaded — check remote output above", "[!]".yellow().bold());
        }
        println!();
        return;
    }

    // ══════════════════════════════════════════
    //  OFFLINE MODE (Linux only)
    // ══════════════════════════════════════════
    #[cfg(not(target_os = "linux"))]
    if offline_root.is_some() {
        println!("{}", "  [!] Offline mode is only available on Linux.".red().bold());
        println!("{}", "      Boot from a Linux USB to use offline forensic scanning.".yellow());
        println!();
        return;
    }

    #[cfg(target_os = "linux")]
    if let Some(ref target_root) = offline_root {
        if !root {
            println!("{}", "  [!] Offline scan needs root. Run with: sudo narayanastra --offline /mnt/disk".red().bold());
            println!("{}", "      Continuing anyway (some checks may fail)...\n".yellow());
        }

        println!("  {}\n",
            ">> Offline forensic scan — rootkit CANNOT hide from this...".bold().cyan());

        let start = Instant::now();
        let (tx, rx) = mpsc::channel::<ScanEvent>();

        let target_clone = target_root.clone();
        let h = thread::spawn(move || modules::offline::scan(&target_clone, tx));

        let mut findings = Vec::new();
        for event in rx {
            match event {
                ScanEvent::ModuleStart(name) => {
                    println!("  {} {} {}",
                        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).bright_black(),
                        ">>".cyan().bold(),
                        format!("{} started", name).cyan());
                }
                ScanEvent::ModuleProgress(_name, msg) => {
                    println!("  {} {} {}",
                        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).bright_black(),
                        "[OFFLINE]".bright_black(),
                        msg.bright_black());
                }
                ScanEvent::Finding(finding) => {
                    finding.print_live();
                    findings.push(finding);
                }
                ScanEvent::ModuleDone(name, duration) => {
                    println!("  {} {} {} {}\n",
                        format!("[{}]", chrono::Local::now().format("%H:%M:%S")).bright_black(),
                        "<<".green().bold(),
                        format!("{} complete", name).green(),
                        format!("({:.2}s)", duration.as_secs_f64()).bright_black());
                }
            }
        }

        let _ = h.join();

        let mut report = ScanReport::new(scan_mode.to_string(), hostname, username);
        report.findings = findings;
        report.duration_secs = start.elapsed().as_secs_f64();

        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
        println!("  {} {:.2}s",
            "Offline scan complete in".bold().cyan(),
            report.duration_secs);
        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
        report.print_summary();

        let report_path = "offline_scan_report.txt";
        match report.save_to_file(report_path) {
            Ok(_) => {
                println!("\n  {} {}", "[+] Report:".green().bold(), report_path.white().bold());
                println!("  {} {}", "[+] JSON:".green().bold(), "offline_scan_report.json".white().bold());
            }
            Err(e) => println!("\n  {} {}", "[!] Save failed:".red(), e),
        }
        println!();
        return;
    }

    // ══════════════════════════════════════════
    //  ONE-SHOT MODE
    // ══════════════════════════════════════════
    if watch_interval.is_none() {
        let mod_text = if cfg!(target_os = "windows") { "7 deep checks" } else { "7 deep-scan modules" };
        println!("  {}\n", format!(">> Launching {} in parallel...", mod_text).bold().cyan());
        let start = Instant::now();
        let findings = run_scan(root, full_scan, false);

        let mut report = ScanReport::new(scan_mode.to_string(), hostname, username);
        report.findings = findings;
        report.duration_secs = start.elapsed().as_secs_f64();

        let done_text = if cfg!(target_os = "windows") { "All checks complete in" } else { "All 7 modules complete in" };
        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
        println!("  {} {:.2}s",
            done_text.bold().cyan(),
            report.duration_secs);
        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
        report.print_summary();

        let report_path = "scan_report.txt";
        match report.save_to_file(report_path) {
            Ok(_) => {
                println!("\n  {} {}", "[+] Report:".green().bold(), report_path.white().bold());
                println!("  {} {}", "[+] JSON:".green().bold(), "scan_report.json".white().bold());
            }
            Err(e) => println!("\n  {} {}", "[!] Save failed:".red(), e),
        }
        println!();
        return;
    }

    // ══════════════════════════════════════════
    //  WATCH MODE
    // ══════════════════════════════════════════
    let interval = watch_interval.unwrap();
    let mut seen_keys: HashSet<String> = HashSet::new();
    let mut scan_count: u64 = 0;
    let mut total_new_threats: u64 = 0;

    // Ctrl+C handler for clean shutdown
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, std::sync::atomic::Ordering::SeqCst);
    }).expect("Failed to set Ctrl+C handler");

    println!("  {}\n", ">> Watch mode — initial full scan...".bold().cyan());

    while running.load(std::sync::atomic::Ordering::SeqCst) {
        scan_count += 1;
        let start = Instant::now();
        let is_first = scan_count == 1;

        let findings = run_scan(root, full_scan, !is_first);
        let duration = start.elapsed().as_secs_f64();

        if is_first {
            // ── Initial scan: show full summary ──
            let (mut safe, mut info, mut warn, mut danger) = (0usize, 0usize, 0usize, 0usize);
            for f in &findings {
                seen_keys.insert(f.key());
                match f.severity {
                    Severity::Safe => safe += 1,
                    Severity::Info => info += 1,
                    Severity::Warning => warn += 1,
                    Severity::Danger => danger += 1,
                }
            }

            println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
            println!("  {} {:.2}s  |  {} {}  {} {}  {} {}  {} {}",
                "Initial scan".bold().cyan(), duration,
                "D:".red().bold(), danger.to_string().red().bold(),
                "W:".yellow().bold(), warn.to_string().yellow().bold(),
                "I:".blue(), info,
                "S:".green(), safe);
            println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());

            if danger > 0 {
                println!("  {}", "!! CRITICAL findings detected! Review above.".red().bold());
            } else if warn > 0 {
                println!("  {}", "!! Warnings found. Review above.".yellow().bold());
            } else {
                println!("  {}", ">> Initial scan clean.".green().bold());
            }

            println!("\n  {} {}\n",
                "● Watching...".cyan().bold(),
                format!("(rescan every {}s, Ctrl+C to stop)", interval).bright_black());
        } else {
            // ── Repeat scan: only show NEW Warning/Danger findings ──
            let mut new_findings: Vec<&Finding> = Vec::new();

            for f in &findings {
                let key = f.key();
                if !seen_keys.contains(&key) {
                    if matches!(f.severity, Severity::Warning | Severity::Danger) {
                        new_findings.push(f);
                    }
                    seen_keys.insert(key);
                }
            }

            let ts = chrono::Local::now().format("%H:%M:%S").to_string();

            if new_findings.is_empty() {
                println!("  {} {} {}",
                    format!("[{}]", ts).bright_black(),
                    "●".green(),
                    format!("Scan #{} — no new threats ({:.1}s)", scan_count, duration).bright_black());
            } else {
                total_new_threats += new_findings.len() as u64;

                println!("\n  {} {} {}",
                    format!("[{}]", ts).bright_black(),
                    "▲ NEW THREATS DETECTED".red().bold(),
                    format!("(scan #{}, {:.1}s)", scan_count, duration).bright_black());
                println!("  {}", "─".repeat(60).red());

                for f in &new_findings {
                    f.print_live();
                }

                println!("  {}\n", "─".repeat(60).red());
            }
        }

        // Sleep in small chunks — Ctrl+C stays responsive
        let sleep_until = Instant::now() + std::time::Duration::from_secs(interval);
        while Instant::now() < sleep_until {
            if !running.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    // ── Clean shutdown ──
    println!("\n{}", "══════════════════════════════════════════════════════════════════════".cyan());
    println!("  {} {} scans, {} new threats, {} unique findings tracked",
        "Watch stopped.".bold().cyan(),
        scan_count.to_string().white().bold(),
        total_new_threats.to_string().white().bold(),
        seen_keys.len().to_string().bright_black());
    println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
    println!();
}
