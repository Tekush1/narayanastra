#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use colored::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub enum Severity {
    Safe,
    Info,
    Warning,
    Danger,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Safe => write!(f, "[SAFE]"),
            Severity::Info => write!(f, "[INFO]"),
            Severity::Warning => write!(f, "[WARNING]"),
            Severity::Danger => write!(f, "[DANGER]"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub module: String,
    pub category: String,
    pub message: String,
    pub detail: Option<String>,
    pub timestamp: String,
    /// Stable identity for dedup / watch mode (module:category:subject).
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub mitre: Option<String>,
    /// File or process artifact worth collecting as evidence.
    #[serde(default)]
    pub artifact: Option<String>,
}

impl Finding {
    pub fn new(severity: Severity, module: &str, category: &str, message: &str) -> Self {
        let mut f = Finding {
            severity,
            module: module.to_string(),
            category: category.to_string(),
            message: message.to_string(),
            detail: None,
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            id: format!("{}:{}:{}", module, category, message),
            mitre: mitre_for(category).map(|s| s.to_string()),
            artifact: None,
        };
        if f.mitre.is_none() {
            f.mitre = mitre_for(module).map(|s| s.to_string());
        }
        f
    }

    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    /// Stable subject (e.g. "pid:1234" or a path) so changing counts don't create new ids.
    pub fn subject(mut self, subject: &str) -> Self {
        self.id = format!("{}:{}:{}", self.module, self.category, subject);
        self
    }

    pub fn mitre(mut self, id: &str) -> Self {
        self.mitre = Some(id.to_string());
        self
    }

    pub fn artifact(mut self, path: &str) -> Self {
        self.artifact = Some(path.to_string());
        self
    }

    pub fn print_live(&self) {
        let module_tag = format!("[{}]", self.module);
        let ts = format!("[{}]", self.timestamp.rsplit(' ').next().unwrap_or(&self.timestamp));
        let mitre = self.mitre.as_deref().map(|m| format!(" ({})", m)).unwrap_or_default();
        match self.severity {
            Severity::Safe => println!("  {} {} {} {}", ts.bright_black(), "[SAFE]".green().bold(), module_tag.green(), self.message),
            Severity::Info => println!("  {} {} {} {}", ts.bright_black(), "[INFO]".blue().bold(), module_tag.blue(), self.message),
            Severity::Warning => {
                println!("  {} {} {} {}{}", ts.bright_black(), "[WARNING]".yellow().bold(), module_tag.yellow(), self.message.yellow(), mitre.bright_black())
            }
            Severity::Danger => println!(
                "  {} {} {} {}{}",
                ts.bright_black(),
                "[DANGER]".red().bold(),
                module_tag.red().bold(),
                self.message.red().bold(),
                mitre.bright_black()
            ),
        }
        if let Some(ref detail) = self.detail {
            for line in detail.lines() {
                println!("           {}", line.bright_black());
            }
        }
    }
}

/// Default MITRE ATT&CK technique per finding category (or module).
pub fn mitre_for(category: &str) -> Option<&'static str> {
    let m = match category {
        "Hidden PIDs" | "Hidden Process" | "Hidden Module" | "Rootkit Module" | "Rootkit Signature" | "Rootkit File" | "Ghost PIDs" | "Kernel Hook"
        | "Ftrace Hook" | "Syscall Table" | "Hidden eBPF" | "eBPF Hook" => "T1014",
        "Hidden Ports" | "Hidden Listener" => "T1014",
        "Deleted Binary" | "Fileless" | "Memfd Exec" => "T1620",
        "LD Preload" | "LD_PRELOAD" | "Scanner Injected" => "T1574.006",
        "LD_AUDIT" => "T1574.006",
        "Reverse Shell" => "T1059.004",
        "Crypto Miner" => "T1496",
        "Temp Exec" => "T1036.005",
        "Name Spoof" | "Kthread Disguise" => "T1036.004",
        "Obfuscation" => "T1027",
        "Code Injection" | "Injected Library" | "Deleted Library" => "T1055",
        "Suspicious Port" | "Suspicious Outbound" | "C2 Match" => "T1071",
        "Promiscuous" | "Raw Socket" => "T1040",
        "SUID" | "SGID" | "Hidden SUID" => "T1548.001",
        "Tampered Binary" | "Pkg Integrity" | "Binary Integrity" => "T1554",
        "Suspicious Module" | "Kernel Modules" => "T1547.006",
        "Immutable" => "T1222.002",
        "World-Writable" => "T1222.002",
        "Timestomp" => "T1070.006",
        "Wiped Log" | "Log Wiped" | "Truncated Log" | "Log Gap" | "Log Owner" | "Login Log Wiped" => "T1070.002",
        "History Evasion" | "History Wiped" | "Empty History" => "T1070.003",
        "PAM Backdoor" => "T1556.003",
        "Brute Force" | "Failed Logins" => "T1110",
        "SSH Key" | "SSH Forced Cmd" | "Authorized Keys" => "T1098.004",
        "Cron" | "Cron Persistence" | "At Job" => "T1053.003",
        "Systemd Persistence" | "Systemd Timer" | "Systemd Generator" => "T1543.002",
        "Shell Inject" | "Shell RC" | "Profile Script" => "T1546.004",
        "UID0 Account" | "Empty Password" | "System Account Shell" | "New Account" => "T1136.001",
        "Sudoers" => "T1548.003",
        "SSHD Config" => "T1098",
        "Udev Rule" => "T1546",
        "XDG Autostart" => "T1547.013",
        "MOTD Script" | "Package Hook" | "rc.local" => "T1037",
        "Module Autoload" | "Initramfs Rootkit" | "Initramfs Hook" | "Initramfs Script" => "T1547.006",
        "GRUB Config" | "GRUB Module" | "Bootloader" => "T1542.003",
        "io_uring" => "T1014",
        "Privileged Container" | "Docker Socket" | "Host Namespace" => "T1611",
        "ROOTKIT" | "KHOOKS" | "EBPF" => "T1014",
        "PERSIST" => "T1547",
        _ => return None,
    };
    Some(m)
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    ModuleStart(String),
    ModuleProgress(String, String),
    Finding(Finding),
    ModuleDone(String, std::time::Duration),
}

pub type Sender = mpsc::Sender<ScanEvent>;

pub fn send(tx: &Sender, f: Finding) {
    let _ = tx.send(ScanEvent::Finding(f));
}

pub fn progress(tx: &Sender, module: &str, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(module.to_string(), msg.to_string()));
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub version: String,
    pub scan_mode: String,
    pub hostname: String,
    pub username: String,
    pub platform: String,
    pub timestamp: String,
    pub duration_secs: f64,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub crashed_modules: Vec<String>,
}

impl ScanReport {
    pub fn new(scan_mode: String, hostname: String, username: String) -> Self {
        ScanReport {
            version: VERSION.to_string(),
            scan_mode,
            hostname,
            username,
            platform: std::env::consts::OS.to_string(),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            duration_secs: 0.0,
            findings: Vec::new(),
            crashed_modules: Vec::new(),
        }
    }

    /// Keep one finding per id (the most severe). Order is preserved.
    pub fn dedup(&mut self) {
        let mut best: HashMap<String, usize> = HashMap::new();
        let mut keep: Vec<Finding> = Vec::new();
        for f in self.findings.drain(..) {
            match best.get(&f.id) {
                Some(&i) => {
                    if f.severity > keep[i].severity {
                        keep[i] = f;
                    }
                }
                None => {
                    best.insert(f.id.clone(), keep.len());
                    keep.push(f);
                }
            }
        }
        self.findings = keep;
    }

    pub fn count_by_severity(&self) -> (usize, usize, usize, usize) {
        let (mut s, mut i, mut w, mut d) = (0, 0, 0, 0);
        for f in &self.findings {
            match f.severity {
                Severity::Safe => s += 1,
                Severity::Info => i += 1,
                Severity::Warning => w += 1,
                Severity::Danger => d += 1,
            }
        }
        (s, i, w, d)
    }

    /// 0 clean, 1 warnings, 2 danger, 3 scanner error (crashed module).
    pub fn exit_code(&self) -> i32 {
        let (_, _, w, d) = self.count_by_severity();
        if d > 0 {
            2
        } else if !self.crashed_modules.is_empty() {
            3
        } else if w > 0 {
            1
        } else {
            0
        }
    }

    pub fn print_summary(&self) {
        let (safe, info, warn, danger) = self.count_by_severity();
        let total = safe + info + warn + danger;
        println!();
        println!(
            "  {} {}   {} {}   {} {}   {} {}   {} {}",
            "Total:".bold(),
            total.to_string().white().bold(),
            "DANGER:".red().bold(),
            danger.to_string().red().bold(),
            "WARNING:".yellow().bold(),
            warn.to_string().yellow().bold(),
            "INFO:".blue().bold(),
            info,
            "SAFE:".green().bold(),
            safe
        );
        println!();
        if !self.crashed_modules.is_empty() {
            println!("  {} {}", "!! Incomplete scan — crashed modules:".red().bold(), self.crashed_modules.join(", "));
        }
        if danger > 0 {
            println!("  {}", "!! CRITICAL: Dangerous findings detected! Investigate immediately.".red().bold());
        } else if warn > 0 {
            println!("  {}", "!! Warnings found. Review recommended.".yellow().bold());
        } else {
            println!("  {}", ">> No threats detected by the checks that ran.".green().bold());
        }
    }

    fn modules_in_order(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for f in &self.findings {
            if !seen.contains(&f.module) {
                seen.push(f.module.clone());
            }
        }
        seen
    }

    pub fn to_text(&self) -> String {
        let mut s = String::new();
        s.push_str("╔══════════════════════════════════════════════════════════════════════╗\n");
        s.push_str(&format!("║   Narayanastra v{:<8} — Deep Scan Report | CyberHX                  ║\n", self.version));
        s.push_str("╚══════════════════════════════════════════════════════════════════════╝\n\n");
        s.push_str(&format!(
            "  Scan Mode : {}\n  Hostname  : {}\n  Username  : {}\n  Platform  : {}\n  Timestamp : {}\n  Duration  : {:.2}s\n\n",
            self.scan_mode, self.hostname, self.username, self.platform, self.timestamp, self.duration_secs
        ));
        for module in self.modules_in_order() {
            s.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            s.push_str(&format!("  MODULE: {}\n", module));
            s.push_str("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            for f in self.findings.iter().filter(|f| f.module == module) {
                let mitre = f.mitre.as_deref().map(|m| format!(" ({})", m)).unwrap_or_default();
                s.push_str(&format!("  {} [{}] {}{}\n", f.severity, f.category, f.message, mitre));
                if let Some(ref d) = f.detail {
                    for line in d.lines() {
                        s.push_str(&format!("           {}\n", line));
                    }
                }
            }
            s.push('\n');
        }
        let (safe, info, warn, danger) = self.count_by_severity();
        s.push_str("══════════════════════════════════════════════════════════════════════\n  SUMMARY\n");
        s.push_str("══════════════════════════════════════════════════════════════════════\n");
        s.push_str(&format!("  Total: {}  |  DANGER: {}  |  WARNING: {}  |  INFO: {}  |  SAFE: {}\n", safe + info + warn + danger, danger, warn, info, safe));
        if !self.crashed_modules.is_empty() {
            s.push_str(&format!("  Incomplete — crashed modules: {}\n", self.crashed_modules.join(", ")));
        }
        s.push_str(&format!("\n  Narayanastra v{} | {}\n  Built by Kushagra Dwivedi | CyberHX\n", self.version, self.timestamp));
        s
    }

    pub fn to_ndjson(&self) -> String {
        let mut s = String::new();
        for f in &self.findings {
            let mut v = serde_json::to_value(f).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                o.insert("hostname".into(), self.hostname.clone().into());
                o.insert("scanner".into(), format!("narayanastra/{}", self.version).into());
            }
            s.push_str(&v.to_string());
            s.push('\n');
        }
        s
    }

    pub fn to_sarif(&self) -> String {
        let mut rules: BTreeMap<String, serde_json::Value> = BTreeMap::new();
        let mut results = Vec::new();
        for f in &self.findings {
            if matches!(f.severity, Severity::Safe) {
                continue;
            }
            let rule_id = format!("{}/{}", f.module, f.category.replace(' ', "-"));
            rules.entry(rule_id.clone()).or_insert_with(|| {
                serde_json::json!({
                    "id": rule_id,
                    "name": f.category,
                    "shortDescription": {"text": format!("{} — {}", f.module, f.category)},
                    "properties": {"tags": f.mitre.iter().collect::<Vec<_>>()}
                })
            });
            let level = match f.severity {
                Severity::Danger => "error",
                Severity::Warning => "warning",
                _ => "note",
            };
            let uri = f.artifact.clone().unwrap_or_else(|| format!("host/{}", self.hostname));
            results.push(serde_json::json!({
                "ruleId": rule_id,
                "level": level,
                "message": {"text": match &f.detail { Some(d) => format!("{}\n{}", f.message, d), None => f.message.clone() }},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri.trim_start_matches('/')}}}],
                "partialFingerprints": {"narayanastraId": f.id},
            }));
        }
        let sarif = serde_json::json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {
                    "name": "Narayanastra",
                    "version": self.version,
                    "informationUri": "https://github.com/Tekush1/narayanastra",
                    "rules": rules.into_values().collect::<Vec<_>>()
                }},
                "results": results
            }]
        });
        serde_json::to_string_pretty(&sarif).unwrap_or_default()
    }

    pub fn to_html(&self) -> String {
        fn esc(s: &str) -> String {
            s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
        }
        let (safe, info, warn, danger) = self.count_by_severity();
        let mut mitre: BTreeMap<String, (usize, Severity)> = BTreeMap::new();
        for f in &self.findings {
            if let Some(m) = &f.mitre {
                if f.severity >= Severity::Warning {
                    let e = mitre.entry(m.clone()).or_insert((0, f.severity));
                    e.0 += 1;
                    if f.severity > e.1 {
                        e.1 = f.severity;
                    }
                }
            }
        }
        let mut h = String::new();
        h.push_str("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        h.push_str(&format!("<title>Narayanastra report — {}</title>", esc(&self.hostname)));
        h.push_str(
            "<style>
:root{--bg:#0b0f17;--card:#121826;--line:#1f2a3d;--text:#e6ebf5;--muted:#8a96ad;--danger:#ff4d5e;--warn:#ffb020;--info:#4da3ff;--safe:#2ecc71}
*{box-sizing:border-box}body{margin:0;font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}
header{padding:28px 32px;border-bottom:1px solid var(--line)}h1{margin:0;font-size:22px}header p{margin:4px 0 0;color:var(--muted)}
main{padding:24px 32px;max-width:1200px}.tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}.tile b{display:block;font-size:26px}
.d b{color:var(--danger)}.w b{color:var(--warn)}.i b{color:var(--info)}.s b{color:var(--safe)}
h2{font-size:15px;margin:28px 0 10px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
td,th{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{color:var(--muted);font-weight:600}
.sev{font-weight:700;white-space:nowrap}.Danger{color:var(--danger)}.Warning{color:var(--warn)}.Info{color:var(--info)}.Safe{color:var(--safe)}
pre{margin:4px 0 0;white-space:pre-wrap;color:var(--muted);font:12px/1.4 ui-monospace,Menlo,monospace}
.grid{display:flex;flex-wrap:wrap;gap:8px}.cell{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px}
.cell.Danger{border-color:var(--danger)}.cell.Warning{border-color:var(--warn)}code{font-family:ui-monospace,Menlo,monospace}
</style></head><body>",
        );
        h.push_str(&format!(
            "<header><h1>नारायणास्त्र — Narayanastra v{}</h1><p>{} · {} · {} mode · {:.1}s</p></header><main>",
            esc(&self.version),
            esc(&self.hostname),
            esc(&self.timestamp),
            esc(&self.scan_mode),
            self.duration_secs
        ));
        h.push_str(&format!(
            "<div class=\"tiles\"><div class=\"tile d\"><b>{}</b>Danger</div><div class=\"tile w\"><b>{}</b>Warning</div><div class=\"tile i\"><b>{}</b>Info</div><div class=\"tile s\"><b>{}</b>Safe</div></div>",
            danger, warn, info, safe
        ));
        if !self.crashed_modules.is_empty() {
            h.push_str(&format!("<p class=\"Danger\">Incomplete scan — crashed modules: {}</p>", esc(&self.crashed_modules.join(", "))));
        }
        if !mitre.is_empty() {
            h.push_str("<h2>MITRE ATT&amp;CK coverage (warning+)</h2><div class=\"grid\">");
            for (t, (n, sev)) in &mitre {
                h.push_str(&format!(
                    "<a class=\"cell {:?}\" href=\"https://attack.mitre.org/techniques/{}/\" style=\"color:inherit;text-decoration:none\"><code>{}</code> × {}</a>",
                    sev,
                    esc(&t.replace('.', "/")),
                    esc(t),
                    n
                ));
            }
            h.push_str("</div>");
        }
        for module in self.modules_in_order() {
            h.push_str(&format!("<h2>{}</h2><table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>ATT&amp;CK</th></tr>", esc(&module)));
            let mut fs: Vec<&Finding> = self.findings.iter().filter(|f| f.module == module).collect();
            fs.sort_by_key(|f| std::cmp::Reverse(f.severity));
            for f in fs {
                h.push_str(&format!(
                    "<tr><td class=\"sev {:?}\">{:?}</td><td>{}</td><td>{}{}</td><td>{}</td></tr>",
                    f.severity,
                    f.severity,
                    esc(&f.category),
                    esc(&f.message),
                    f.detail.as_ref().map(|d| format!("<pre>{}</pre>", esc(d))).unwrap_or_default(),
                    f.mitre.as_deref().map(esc).unwrap_or_default()
                ));
            }
            h.push_str("</table>");
        }
        h.push_str("<p style=\"color:var(--muted);margin-top:32px\">Built by Kushagra Dwivedi · CyberHX · <a style=\"color:var(--info)\" href=\"https://github.com/Tekush1/narayanastra\">github.com/Tekush1/narayanastra</a></p></main></body></html>");
        h
    }
}

// ───────────────────────── safe output ─────────────────────────

/// Create a new private output directory. Fails if it already exists (no symlink tricks).
pub fn create_output_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).recursive(false).create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::DirBuilder::new().recursive(false).create(path)
    }
}

/// Create a brand-new file (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600) — never writes
/// through a pre-planted symlink, even when running as root in /tmp.
pub fn create_new_file(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    o.open(path)
}

pub fn write_new(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let mut f = create_new_file(path)?;
    f.write_all(content)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
    Ndjson,
    Sarif,
    Html,
}

impl Format {
    pub fn parse(s: &str) -> Option<Format> {
        match s.trim().to_lowercase().as_str() {
            "text" | "txt" => Some(Format::Text),
            "json" => Some(Format::Json),
            "ndjson" | "jsonl" => Some(Format::Ndjson),
            "sarif" => Some(Format::Sarif),
            "html" => Some(Format::Html),
            _ => None,
        }
    }
}

/// Write the report in every requested format into `dir`. Returns written paths.
pub fn write_report(report: &ScanReport, dir: &Path, formats: &[Format]) -> std::io::Result<Vec<PathBuf>> {
    let mut written = Vec::new();
    let mut fmts: Vec<Format> = vec![Format::Text, Format::Json];
    for f in formats {
        if !fmts.contains(f) {
            fmts.push(*f);
        }
    }
    for f in fmts {
        let (name, content) = match f {
            Format::Text => ("report.txt", report.to_text()),
            Format::Json => ("report.json", serde_json::to_string_pretty(report).unwrap_or_default()),
            Format::Ndjson => ("findings.ndjson", report.to_ndjson()),
            Format::Sarif => ("report.sarif", report.to_sarif()),
            Format::Html => ("report.html", report.to_html()),
        };
        let p = dir.join(name);
        write_new(&p, content.as_bytes())?;
        written.push(p);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ScanReport {
        let mut r = ScanReport::new("User".into(), "box".into(), "kush".into());
        r.findings.push(Finding::new(Severity::Warning, "NETWORK", "Hidden Ports", "1 port hidden").subject("tcp:31337"));
        r.findings.push(Finding::new(Severity::Danger, "NETWORK", "Hidden Ports", "2 ports hidden").subject("tcp:31337"));
        r.findings.push(Finding::new(Severity::Info, "PROCESS", "Summary", "<script>x</script>"));
        r
    }

    #[test]
    fn dedup_keeps_most_severe() {
        let mut r = sample();
        r.dedup();
        assert_eq!(r.findings.len(), 2);
        assert_eq!(r.findings[0].severity, Severity::Danger);
        assert_eq!(r.exit_code(), 2);
    }

    #[test]
    fn mitre_and_formats() {
        let r = sample();
        assert_eq!(r.findings[0].mitre.as_deref(), Some("T1014"));
        let sarif: serde_json::Value = serde_json::from_str(&r.to_sarif()).unwrap();
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 3);
        let html = r.to_html();
        assert!(html.contains("&lt;script&gt;"));
        assert!(!html.contains("<script>x"));
        assert_eq!(r.to_ndjson().lines().count(), 3);
    }

    #[test]
    fn output_never_follows_symlinks() {
        let d = crate::util::testutil::tempdir("out");
        let target = d.join("victim");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, d.join("report.txt")).unwrap();
        assert!(write_new(&d.join("report.txt"), b"x").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let _ = std::fs::remove_dir_all(d);
    }
}
