mod config;
#[cfg(target_os = "linux")]
mod hash;
mod logo;
mod modules;
mod report;

#[cfg(target_os = "linux")]
mod baseline;
#[cfg(target_os = "linux")]
mod netdiag;
#[cfg(target_os = "linux")]
mod pkg;
#[cfg(target_os = "linux")]
mod procfs;
#[cfg(target_os = "linux")]
mod util;

use clap::{Args, Parser, Subcommand};
use colored::*;
use config::ScanConfig;
use report::{Finding, Format, ScanEvent, ScanReport, Severity};
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(
    name = "narayanastra",
    version,
    about = "Narayanastra — post-compromise scanner for rootkits, backdoors and silent threats",
    after_help = "Examples:\n  narayanastra                               quick scan\n  sudo narayanastra --full                   full deep scan\n  sudo narayanastra -f --watch 60            full scan, re-scan every 60s\n  sudo narayanastra --offline /mnt/disk      offline forensic scan\n  sudo narayanastra --container web1         scan a container's filesystem\n  narayanastra --remote ubuntu@host -f       scan a server over SSH\n  sudo narayanastra --format html,sarif      extra report formats\n  sudo narayanastra baseline save base.json --key-file k\n  sudo narayanastra baseline diff base.json --key-file k\n  narayanastra crossdiff --live live.json --offline disk.json"
)]
struct Cli {
    #[command(flatten)]
    opts: Opts,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Args, Debug, Clone)]
struct Opts {
    /// Full deep scan: PID sweep, port bind probe, recursive walks, full package verify (needs root)
    #[arg(short, long, global = true)]
    full: bool,
    /// Re-scan every N seconds and alert only on new findings
    #[arg(short, long, num_args = 0..=1, default_missing_value = "30", value_name = "SECS")]
    watch: Option<u64>,
    /// Offline forensic scan of a mounted disk (Linux)
    #[arg(long, value_name = "PATH", conflicts_with_all = ["remote", "container"])]
    offline: Option<PathBuf>,
    /// Scan a running container's filesystem (container id prefix or PID)
    #[arg(long, value_name = "ID|PID", conflicts_with = "remote")]
    container: Option<String>,
    /// Remote scan over SSH: upload, run, download report, clean up
    #[arg(long, value_name = "USER@HOST")]
    remote: Option<String>,
    /// Output directory (default: ./narayanastra-<host>-<timestamp>)
    #[arg(short, long, value_name = "DIR", global = true)]
    output_dir: Option<PathBuf>,
    /// Extra report formats: text,json,ndjson,sarif,html (text+json are always written)
    #[arg(long, value_delimiter = ',', value_name = "FMT")]
    format: Vec<String>,
    /// Only print the summary
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Run only these modules: rootkit,process,network,files,memory,logs,antifor,persist,iouring,ebpf,khooks,container
    #[arg(long, value_delimiter = ',', value_name = "LIST")]
    modules: Vec<String>,
    /// Disable colours
    #[arg(long, global = true)]
    no_color: bool,
    /// Trusted path->sha256 JSON for integrity checks (make it on a known-clean system)
    #[arg(long, value_name = "FILE")]
    hashdb: Option<String>,
    /// Extra threat-feed file (IPs / CIDRs, one per line)
    #[arg(long, value_name = "FILE")]
    feed: Option<String>,
    /// POST Danger findings to a Slack/Discord-compatible webhook (uses /usr/bin/curl)
    #[arg(long, value_name = "URL")]
    webhook: Option<String>,
    /// Copy flagged artifacts (binaries, scripts, /proc/PID/exe) into <output-dir>/evidence with sha256 manifest
    #[arg(long)]
    collect: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Save or compare an integrity baseline
    Baseline {
        #[command(subcommand)]
        action: BaselineCmd,
    },
    /// Compare a LIVE snapshot with an OFFLINE snapshot of the same disk (finds what the running OS hides)
    Crossdiff {
        #[arg(long, value_name = "FILE")]
        live: String,
        #[arg(long, value_name = "FILE")]
        offline: String,
    },
}

#[derive(Subcommand, Debug)]
enum BaselineCmd {
    /// Snapshot binaries, SUIDs, persistence files, users, listeners, modules, eBPF
    Save {
        file: PathBuf,
        /// Snapshot an offline root instead of the live system
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,
        /// HMAC-sign the snapshot with this key file
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,
    },
    /// Report what changed since the snapshot
    Diff {
        file: String,
        #[arg(long, value_name = "FILE")]
        key_file: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,
    },
}

fn print_banner() {
    let (art, width) = logo::lines(4);
    let centre = |text: &str| " ".repeat(width.saturating_sub(text.chars().count()) / 2);
    println!();
    for line in art {
        println!("  {}", line);
    }
    let tagline = "Post-Compromise Rootkit & Backdoor Scanner";
    let credit = format!("v{} | CyberHX | Built by Kushagra Dwivedi", report::VERSION);
    println!();
    println!("  {}{}", centre(tagline), tagline.bold());
    println!("  {}{}", centre(&credit), credit.dimmed());
    println!();
}

#[cfg(unix)]
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn is_root() -> bool {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    std::process::Command::new(format!(r"{}\System32\net.exe", root)).arg("session").output().map(|o| o.status.success()).unwrap_or(false)
}

fn hostname() -> String {
    #[cfg(target_os = "linux")]
    {
        util::read_string_capped("/etc/hostname", 4096).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).unwrap_or_else(|| "unknown".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    }
}

type ModFn = fn(&ScanConfig, report::Sender);

#[cfg(target_os = "linux")]
fn module_table() -> Vec<(&'static str, ModFn)> {
    use modules::*;
    vec![
        ("rootkit", rootkit::scan as ModFn),
        ("process", process::scan),
        ("network", network::scan),
        ("files", files::scan),
        ("memory", memory::scan),
        ("logs", logs::scan),
        ("antifor", antiforensics::scan),
        ("persist", persistence::scan),
        ("iouring", iouring::scan),
        ("ebpf", ebpf::scan),
        ("khooks", kernelhooks::scan),
        ("container", container::scan),
    ]
}

#[cfg(target_os = "windows")]
fn module_table() -> Vec<(&'static str, ModFn)> {
    vec![("windows", modules::windows::scan as ModFn)]
}

/// Detect if the scanner process itself is being injected (LD_PRELOAD / ld.so.preload).
#[cfg(target_os = "linux")]
fn self_check() -> Option<Finding> {
    let preload = util::read_string_capped("/etc/ld.so.preload", 65536).map(|s| s.trim().to_string()).unwrap_or_default();
    let env = std::env::var("LD_PRELOAD").unwrap_or_default();
    let exe = std::env::current_exe().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let mut odd = Vec::new();
    if let Some(maps) = procfs::maps(std::process::id()) {
        for m in maps.iter().filter(|m| m.is_exec() && !m.path.is_empty() && !m.path.starts_with('[')) {
            let std_lib = ["/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/lib32/"].iter().any(|p| m.path.starts_with(p));
            if m.path != exe && !std_lib && !odd.contains(&m.path) {
                odd.push(m.path.clone());
            }
        }
    }
    if preload.is_empty() && env.is_empty() && odd.is_empty() {
        return None;
    }
    let mut detail = Vec::new();
    if !preload.is_empty() {
        detail.push(format!("/etc/ld.so.preload: {}", preload));
    }
    if !env.is_empty() {
        detail.push(format!("LD_PRELOAD={}", env));
    }
    if !odd.is_empty() {
        detail.push(format!("Unexpected code mapped into the scanner: {}", odd.join(", ")));
    }
    detail.push("Use the static musl build (immune to LD_PRELOAD) or the offline mode for trustworthy results.".into());
    Some(
        Finding::new(Severity::Danger, "ROOTKIT", "Scanner Injected", "Libraries are being injected into Narayanastra itself — userland rootkit active")
            .with_detail(&detail.join("\n"))
            .subject("self-check"),
    )
}

#[cfg(not(target_os = "linux"))]
fn self_check() -> Option<Finding> {
    None
}

struct RunResult {
    findings: Vec<Finding>,
    crashed: Vec<String>,
}

fn run_scan(cfg: &Arc<ScanConfig>, selected: &[(&'static str, ModFn)], quiet: bool) -> RunResult {
    let (tx, rx) = mpsc::channel::<ScanEvent>();
    let mut handles = Vec::new();
    for (name, f) in selected {
        let tx = tx.clone();
        let cfg = cfg.clone();
        let f = *f;
        let name = *name;
        handles.push((name, thread::Builder::new().name(name.into()).spawn(move || f(&cfg, tx)).expect("spawn")));
    }
    drop(tx);
    let total = selected.len();
    let mut done = 0;
    let mut findings = Vec::new();
    for ev in rx {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        match ev {
            ScanEvent::ModuleStart(n) => {
                if !quiet {
                    println!("  {} {} {}", format!("[{}]", ts).bright_black(), ">>".cyan().bold(), format!("{} started", n).cyan());
                }
            }
            ScanEvent::ModuleProgress(n, m) => {
                if !quiet {
                    println!("  {} {} {}", format!("[{}]", ts).bright_black(), format!("[{}]", n).bright_black(), m.bright_black());
                }
            }
            ScanEvent::Finding(f) => {
                if !quiet {
                    f.print_live();
                }
                findings.push(f);
            }
            ScanEvent::ModuleDone(n, d) => {
                done += 1;
                if !quiet {
                    println!(
                        "  {} {} {} {}\n",
                        format!("[{}]", ts).bright_black(),
                        "<<".green().bold(),
                        format!("{} complete", n).green(),
                        format!("({:.2}s) [{}/{}]", d.as_secs_f64(), done, total).bright_black()
                    );
                }
            }
        }
    }
    let mut crashed = Vec::new();
    for (name, h) in handles {
        if h.join().is_err() {
            crashed.push(name.to_string());
            findings.push(
                Finding::new(Severity::Danger, "SCANNER", "Module Crashed", &format!("Module '{}' crashed — its results are incomplete", name))
                    .with_detail("A malformed file or a hostile environment can crash a module; re-run it alone with --modules to investigate")
                    .subject(&format!("crash:{}", name)),
            );
        }
    }
    RunResult { findings, crashed }
}

fn default_output_dir() -> PathBuf {
    PathBuf::from(format!("narayanastra-{}-{}", hostname().replace(['/', ' '], "_"), chrono::Local::now().format("%Y%m%d-%H%M%S")))
}

fn finish(mut report: ScanReport, opts: &Opts, formats: &[Format]) -> i32 {
    report.dedup();
    report.print_summary();
    let dir = opts.output_dir.clone().unwrap_or_else(default_output_dir);
    if let Err(e) = report::create_output_dir(&dir) {
        println!("\n  {} cannot create {}: {} (it must not exist yet)", "[!]".red().bold(), dir.display(), e);
        return 3;
    }
    match report::write_report(&report, &dir, formats) {
        Ok(paths) => {
            println!();
            for p in paths {
                println!("  {} {}", "[+]".green().bold(), p.display().to_string().white().bold());
            }
        }
        Err(e) => println!("\n  {} {}", "[!] Save failed:".red(), e),
    }
    #[cfg(target_os = "linux")]
    if opts.collect {
        collect_evidence(&report, &dir.join("evidence"));
    }
    if let Some(url) = &opts.webhook {
        send_webhook(url, &report.findings.iter().filter(|f| f.severity == Severity::Danger).collect::<Vec<_>>(), &report.hostname);
    }
    println!();
    report.exit_code()
}

#[cfg(target_os = "linux")]
fn collect_evidence(report: &ScanReport, dir: &Path) {
    if report::create_output_dir(dir).is_err() {
        return;
    }
    let mut manifest = Vec::new();
    let mut seen = HashSet::new();
    for f in &report.findings {
        let art = match &f.artifact {
            Some(a) if f.severity >= Severity::Warning && seen.insert(a.clone()) => a.clone(),
            _ => continue,
        };
        let data = match util::read_capped(&art, 200 * 1024 * 1024).or_else(|| util::read_proc_bytes(&art)) {
            Some(d) => d,
            None => continue,
        };
        let sha = hash::hex(&hash::sha256(&data));
        let safe_name = format!("{}_{}", &sha[..12], art.trim_start_matches('/').replace('/', "_"));
        if report::write_new(&dir.join(&safe_name), &data).is_ok() {
            manifest.push(serde_json::json!({"source": art, "file": safe_name, "sha256": sha, "size": data.len(), "finding": f.id, "severity": format!("{:?}", f.severity)}));
        }
    }
    let _ = report::write_new(&dir.join("manifest.json"), serde_json::to_string_pretty(&manifest).unwrap_or_default().as_bytes());
    println!("  {} {} artifact(s) collected in {}", "[+]".green().bold(), manifest.len(), dir.display());
}

fn send_webhook(url: &str, dangers: &[&Finding], host: &str) {
    if dangers.is_empty() {
        return;
    }
    let lines: Vec<String> = dangers.iter().take(20).map(|f| format!("• [{}] {}", f.module, f.message)).collect();
    let text = format!("Narayanastra on {}: {} DANGER finding(s)\n{}", host, dangers.len(), lines.join("\n"));
    let body = serde_json::json!({"text": text, "content": text}).to_string();
    #[cfg(target_os = "linux")]
    {
        let r = util::run_cmd(
            &["/usr/bin/curl", "/bin/curl"],
            &["-sS", "-m", "15", "-X", "POST", "-H", "Content-Type: application/json", "--data-binary", "@-", url],
            std::time::Duration::from_secs(20),
            65536,
            Some(body.into_bytes()),
        );
        if r.map(|o| !o.ok()).unwrap_or(true) {
            println!("  {} webhook delivery failed", "[!]".yellow());
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (body, url);
}

fn parse_formats(v: &[String]) -> Result<Vec<Format>, String> {
    v.iter().map(|s| Format::parse(s).ok_or_else(|| format!("unknown format '{}' (text,json,ndjson,sarif,html)", s))).collect()
}

fn main() {
    let cli = Cli::parse();
    let opts = cli.opts.clone();
    if opts.no_color {
        colored::control::set_override(false);
    }
    let formats = match parse_formats(&opts.format) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {}", e);
            std::process::exit(3);
        }
    };
    if !opts.quiet {
        print_banner();
    }
    let root = is_root();
    let cfg = Arc::new(ScanConfig { is_root: root, full: opts.full, hashdb: opts.hashdb.clone(), feed: opts.feed.clone() });

    #[cfg(target_os = "linux")]
    if let Some(cmd) = &cli.cmd {
        std::process::exit(run_subcommand(cmd, &opts, &formats));
    }
    #[cfg(not(target_os = "linux"))]
    if cli.cmd.is_some() {
        eprintln!("baseline/crossdiff are Linux-only");
        std::process::exit(3);
    }

    if opts.full && !root {
        println!("{}", "  [!] --full requested without root — root-only checks will be skipped.".yellow().bold());
        println!("{}", "      Run: sudo narayanastra --full\n".yellow());
    }

    if let Some(host) = &opts.remote {
        std::process::exit(remote_scan(host, &opts));
    }

    #[cfg(target_os = "linux")]
    if opts.offline.is_some() || opts.container.is_some() {
        std::process::exit(offline_scan(&cfg, &opts, &formats));
    }
    #[cfg(not(target_os = "linux"))]
    if opts.offline.is_some() || opts.container.is_some() {
        eprintln!("Offline/container mode is Linux-only. Boot a Linux USB to scan this disk.");
        std::process::exit(3);
    }

    let table = module_table();
    let selected: Vec<(&'static str, ModFn)> = if opts.modules.is_empty() {
        table
    } else {
        let want: Vec<String> = opts.modules.iter().map(|m| m.trim().to_lowercase()).collect();
        let unknown: Vec<&String> = want.iter().filter(|w| !table.iter().any(|(n, _)| n == &w.as_str())).collect();
        if !unknown.is_empty() {
            eprintln!("error: unknown module(s) {:?}. Available: {}", unknown, table.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(","));
            std::process::exit(3);
        }
        table.into_iter().filter(|(n, _)| want.iter().any(|w| w == n)).collect()
    };

    let scan_mode = if root && opts.full {
        "Full (root)"
    } else if root {
        "Quick (root)"
    } else {
        "User"
    };
    let host = hostname();
    let user = std::env::var("SUDO_USER").or_else(|_| std::env::var("USER")).or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "unknown".into());
    if !opts.quiet {
        println!("  {} {}", "Scan Mode:".bold(), scan_mode.cyan());
        println!("  {} {}", "Hostname:".bold(), host.cyan());
        println!("  {} {}", "User:".bold(), user.cyan());
        println!("  {} {}", "Modules:".bold(), selected.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ").cyan());
        if let Some(i) = opts.watch {
            println!("  {} every {}s (Ctrl+C to stop)", "Watch:".bold(), i);
        }
        println!();
    }

    let injected = self_check();
    if let Some(f) = &injected {
        f.print_live();
        println!();
    }

    if opts.watch.is_none() {
        let start = Instant::now();
        let r = run_scan(&cfg, &selected, opts.quiet);
        let mut report = ScanReport::new(scan_mode.into(), host, user);
        report.findings = r.findings;
        if let Some(f) = injected {
            report.findings.insert(0, f);
        }
        report.crashed_modules = r.crashed;
        report.duration_secs = start.elapsed().as_secs_f64();
        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
        println!("  {} {:.2}s", format!("{} module(s) complete in", selected.len()).bold().cyan(), report.duration_secs);
        println!("{}", "══════════════════════════════════════════════════════════════════════".cyan());
        std::process::exit(finish(report, &opts, &formats));
    }

    // ── watch mode ──
    let interval = opts.watch.unwrap_or(30).max(5);
    let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let r2 = running.clone();
    let _ = ctrlc::set_handler(move || r2.store(false, std::sync::atomic::Ordering::SeqCst));
    let mut seen: HashSet<String> = HashSet::new();
    let mut all: Vec<Finding> = Vec::new();
    let mut crashed_all: Vec<String> = Vec::new();
    let mut scans = 0u64;
    let mut new_threats = 0u64;
    let start_all = Instant::now();
    while running.load(std::sync::atomic::Ordering::SeqCst) {
        scans += 1;
        let first = scans == 1;
        let t = Instant::now();
        let r = run_scan(&cfg, &selected, !first || opts.quiet);
        for c in r.crashed {
            if !crashed_all.contains(&c) {
                crashed_all.push(c);
            }
        }
        let mut fresh = Vec::new();
        for f in r.findings {
            if seen.insert(f.id.clone()) {
                if !first && f.severity >= Severity::Warning {
                    fresh.push(f.clone());
                }
                all.push(f);
            }
        }
        let ts = chrono::Local::now().format("%H:%M:%S");
        if first {
            println!("  {} initial scan done in {:.1}s — watching (every {}s, Ctrl+C to stop)\n", "●".cyan().bold(), t.elapsed().as_secs_f64(), interval);
        } else if fresh.is_empty() {
            println!("  {} {} scan #{} — no new threats ({:.1}s)", format!("[{}]", ts).bright_black(), "●".green(), scans, t.elapsed().as_secs_f64());
        } else {
            new_threats += fresh.len() as u64;
            println!("\n  {} {} (scan #{})", format!("[{}]", ts).bright_black(), "▲ NEW THREATS DETECTED".red().bold(), scans);
            for f in &fresh {
                f.print_live();
            }
            if let Some(url) = &opts.webhook {
                send_webhook(url, &fresh.iter().filter(|f| f.severity == Severity::Danger).collect::<Vec<_>>(), &host);
            }
            println!();
        }
        let until = Instant::now() + std::time::Duration::from_secs(interval);
        while Instant::now() < until && running.load(std::sync::atomic::Ordering::SeqCst) {
            thread::sleep(std::time::Duration::from_millis(200));
        }
    }
    println!("\n  {} {} scans, {} new threats, {} unique findings", "Watch stopped.".bold().cyan(), scans, new_threats, seen.len());
    let mut report = ScanReport::new(format!("Watch ({})", scan_mode), host, user);
    report.findings = all;
    report.crashed_modules = crashed_all;
    report.duration_secs = start_all.elapsed().as_secs_f64();
    std::process::exit(finish(report, &opts, &formats));
}

#[cfg(target_os = "linux")]
fn offline_scan(cfg: &Arc<ScanConfig>, opts: &Opts, formats: &[Format]) -> i32 {
    let (target, label) = if let Some(p) = &opts.offline {
        if !p.is_dir() {
            eprintln!("error: offline path {} is not a directory", p.display());
            return 3;
        }
        (p.to_string_lossy().into_owned(), "Offline (forensic)".to_string())
    } else {
        let want = opts.container.clone().unwrap_or_default();
        let pid = if let Ok(pid) = want.parse::<u32>() {
            Some(pid)
        } else {
            util::proc_pids()
                .into_iter()
                .find(|p| procfs::container_of(*p).map(|c| c == want || c.split(':').nth(1).map(|id| id.starts_with(&want)).unwrap_or(false)).unwrap_or(false))
        };
        match pid {
            Some(p) => (format!("/proc/{}/root", p), format!("Container {} (pid {})", want, p)),
            None => {
                eprintln!("error: no running container matches '{}'", want);
                return 3;
            }
        }
    };
    if !cfg.is_root {
        println!("{}", "  [!] Offline/container scans need root to read the whole filesystem.\n".yellow().bold());
    }
    println!("  {} {}\n  {} {}\n", "Mode:".bold(), label.cyan(), "Target:".bold(), target.cyan());
    let start = Instant::now();
    let (tx, rx) = mpsc::channel::<ScanEvent>();
    let c2 = cfg.clone();
    let t2 = target.clone();
    let h = thread::spawn(move || modules::offline::scan(&t2, &c2, tx));
    let mut findings = Vec::new();
    for ev in rx {
        match ev {
            ScanEvent::Finding(f) => {
                if !opts.quiet {
                    f.print_live();
                }
                findings.push(f);
            }
            ScanEvent::ModuleProgress(_, m) if !opts.quiet => println!("  {} {}", "[OFFLINE]".bright_black(), m.bright_black()),
            _ => {}
        }
    }
    let mut report = ScanReport::new(label, hostname(), std::env::var("USER").unwrap_or_default());
    if h.join().is_err() {
        report.crashed_modules.push("offline".into());
    }
    report.findings = findings;
    report.duration_secs = start.elapsed().as_secs_f64();
    finish(report, opts, formats)
}

#[cfg(target_os = "linux")]
fn run_subcommand(cmd: &Cmd, opts: &Opts, formats: &[Format]) -> i32 {
    let read_key = |p: &Option<PathBuf>| -> Result<Option<Vec<u8>>, String> {
        match p {
            Some(p) => std::fs::read(p).map(Some).map_err(|e| format!("cannot read key file {}: {}", p.display(), e)),
            None => Ok(None),
        }
    };
    match cmd {
        Cmd::Baseline { action: BaselineCmd::Save { file, root, key_file } } => {
            let key = match read_key(key_file) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return 3;
                }
            };
            let r = root.as_ref().map(util::Root::new).unwrap_or_else(util::Root::live);
            println!("  {} snapshotting {} ...", ">>".cyan().bold(), r.base.display());
            let mut snap = baseline::take(&r, opts.full);
            if let Some(k) = key {
                baseline::sign(&mut snap, &k);
            }
            match report::write_new(file, serde_json::to_string_pretty(&snap).unwrap_or_default().as_bytes()) {
                Ok(_) => {
                    println!(
                        "  {} {} ({} files, {} SUID, {} persistence files, {} users{})",
                        "[+] Baseline saved:".green().bold(),
                        file.display(),
                        snap.files.len(),
                        snap.suid.len(),
                        snap.persistence.len(),
                        snap.users.len(),
                        if snap.hmac.is_some() { ", HMAC-signed" } else { "" }
                    );
                    0
                }
                Err(e) => {
                    eprintln!("error: cannot write {}: {} (the file must not exist)", file.display(), e);
                    3
                }
            }
        }
        Cmd::Baseline { action: BaselineCmd::Diff { file, key_file, root } } => {
            let old = match baseline::load(file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("error: {}", e);
                    return 3;
                }
            };
            let mut pre = Vec::new();
            match read_key(key_file) {
                Ok(Some(k)) => {
                    if !baseline::verify_sig(&old, &k) {
                        pre.push(
                            Finding::new(Severity::Danger, "BASELINE", "Baseline Tampered", "Baseline HMAC does not verify — the snapshot file was modified")
                                .subject("hmac"),
                        );
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("error: {}", e);
                    return 3;
                }
            }
            let r = root.as_ref().map(util::Root::new).unwrap_or_else(util::Root::live);
            println!("  {} comparing {} against baseline from {} ...\n", ">>".cyan().bold(), r.base.display(), old.created);
            let now = baseline::take(&r, opts.full);
            pre.extend(baseline::diff(&old, &now));
            if !opts.quiet {
                for f in &pre {
                    f.print_live();
                }
            }
            finish(baseline::report_for(pre, "Baseline diff"), opts, formats)
        }
        Cmd::Crossdiff { live, offline } => {
            let (l, o) = match (baseline::load(live), baseline::load(offline)) {
                (Ok(l), Ok(o)) => (l, o),
                (Err(e), _) | (_, Err(e)) => {
                    eprintln!("error: {}", e);
                    return 3;
                }
            };
            let findings = baseline::crossdiff(&l, &o);
            if !opts.quiet {
                for f in &findings {
                    f.print_live();
                }
            }
            let dir = opts.output_dir.clone().unwrap_or_else(default_output_dir);
            let md = baseline::to_markdown(&findings);
            let csv = baseline::to_csv(&findings);
            let report = baseline::report_for(findings, "Crossdiff (live vs offline)");
            let code = finish(report, &OptsOut::with_dir(opts, &dir), formats);
            let _ = report::write_new(&dir.join("crossdiff.md"), md.as_bytes());
            let _ = report::write_new(&dir.join("crossdiff.csv"), csv.as_bytes());
            println!("  {} {}  {}", "[+]".green().bold(), dir.join("crossdiff.md").display(), dir.join("crossdiff.csv").display());
            code
        }
    }
}

#[cfg(target_os = "linux")]
struct OptsOut;
#[cfg(target_os = "linux")]
impl OptsOut {
    fn with_dir(o: &Opts, dir: &Path) -> Opts {
        let mut n = o.clone();
        n.output_dir = Some(dir.to_path_buf());
        n
    }
}

fn remote_scan(host: &str, opts: &Opts) -> i32 {
    if host.starts_with('-') || host.contains(char::is_whitespace) {
        eprintln!("error: invalid remote host '{}'", host);
        return 3;
    }
    let ssh_opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"];
    let ssh = |cmd: &str| -> Option<std::process::Output> {
        let mut args: Vec<&str> = ssh_opts.to_vec();
        args.extend(["--", host, cmd]);
        std::process::Command::new("ssh").args(&args).output().ok()
    };
    println!("  {}\n", ">> Remote scan over SSH".bold().cyan());

    println!("  {} checking remote architecture...", "[1/5]".cyan().bold());
    let arch = match ssh("uname -sm") {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            println!("  {} cannot reach {} (check SSH keys: ssh {} true)", "[!]".red().bold(), host, host);
            return 3;
        }
    };
    let local = format!("{} {}", if cfg!(target_os = "linux") { "Linux" } else { std::env::consts::OS }, std::env::consts::ARCH);
    if arch != local {
        println!("  {} remote is '{}' but this binary is '{}' — build/copy the matching binary", "[!]".red().bold(), arch, local);
        return 3;
    }
    let dir = match ssh("mktemp -d /tmp/narayanastra.XXXXXXXX") {
        Some(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            println!("  {} mktemp failed on remote", "[!]".red().bold());
            return 3;
        }
    };
    if !dir.starts_with("/tmp/narayanastra.") || !dir.chars().all(|c| c.is_ascii_alphanumeric() || "/._".contains(c)) {
        println!("  {} unexpected remote temp dir '{}'", "[!]".red().bold(), dir);
        return 3;
    }
    println!("  {} uploading scanner to {}:{}", "[2/5]".cyan().bold(), host, dir);
    let self_path = std::env::current_exe().unwrap_or_default();
    let mut scp_args: Vec<String> = ssh_opts.iter().map(|s| s.to_string()).collect();
    scp_args.extend(["--".into(), self_path.to_string_lossy().into_owned(), format!("{}:{}/narayanastra", host, dir)]);
    let ok = std::process::Command::new("scp").args(&scp_args).status().map(|s| s.success()).unwrap_or(false);
    if !ok {
        println!("  {} upload failed", "[!]".red().bold());
        let _ = ssh(&format!("rm -rf -- {}", dir));
        return 3;
    }
    println!("  {} running scan on {}...", "[3/5]".cyan().bold(), host);
    let mut flags = String::from(" --no-color --format json,html,sarif");
    if opts.full {
        flags.push_str(" --full");
    }
    let run = format!("chmod 700 {d}/narayanastra && {d}/narayanastra{f} -o {d}/out; echo EXIT=$?", d = dir, f = flags);
    if let Some(o) = ssh(&run) {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            if !opts.quiet || line.contains("DANGER") {
                println!("  {} {}", "[REMOTE]".bright_black(), line);
            }
        }
    }
    println!("  {} downloading reports...", "[4/5]".cyan().bold());
    let local_dir = opts.output_dir.clone().unwrap_or_else(|| {
        PathBuf::from(format!("narayanastra-remote-{}-{}", host.replace(['@', '.', ':', '/'], "_"), chrono::Local::now().format("%Y%m%d-%H%M%S")))
    });
    let mut scp2: Vec<String> = ssh_opts.iter().map(|s| s.to_string()).collect();
    scp2.extend(["-r".into(), "--".into(), format!("{}:{}/out", host, dir), local_dir.to_string_lossy().into_owned()]);
    let got = std::process::Command::new("scp").args(&scp2).status().map(|s| s.success()).unwrap_or(false);
    println!("  {} cleaning up remote...", "[5/5]".cyan().bold());
    let _ = ssh(&format!("rm -rf -- {}", dir));
    if got {
        println!("\n  {} {}", "[+] Reports:".green().bold(), local_dir.display());
        0
    } else {
        println!("\n  {} reports were not downloaded — see remote output above", "[!]".yellow().bold());
        3
    }
}
