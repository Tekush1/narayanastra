use colored::*;
use serde::Serialize;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::sync::mpsc;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub module: String,
    pub category: String,
    pub message: String,
    pub detail: Option<String>,
    pub timestamp: String,
}

impl Finding {
    pub fn new(severity: Severity, module: &str, category: &str, message: &str) -> Self {
        Finding {
            severity,
            module: module.to_string(),
            category: category.to_string(),
            message: message.to_string(),
            detail: None,
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
        }
    }

    pub fn with_detail(mut self, detail: &str) -> Self {
        self.detail = Some(detail.to_string());
        self
    }

    pub fn key(&self) -> String {
        format!("{}:{}:{}", self.module, self.category, self.message)
    }

    pub fn print_live(&self) {
        let module_tag = format!("[{}]", self.module);
        let ts = format!("[{}]", self.timestamp);
        match self.severity {
            Severity::Safe => {
                println!("  {} {} {} {}",
                    ts.bright_black(),
                    "[SAFE]".green().bold(),
                    module_tag.green(),
                    self.message);
            }
            Severity::Info => {
                println!("  {} {} {} {}",
                    ts.bright_black(),
                    "[INFO]".blue().bold(),
                    module_tag.blue(),
                    self.message);
            }
            Severity::Warning => {
                println!("  {} {} {} {}",
                    ts.bright_black(),
                    "[WARNING]".yellow().bold(),
                    module_tag.yellow(),
                    self.message.yellow().to_string());
            }
            Severity::Danger => {
                println!("  {} {} {} {}",
                    ts.bright_black(),
                    "[DANGER]".red().bold(),
                    module_tag.red().bold(),
                    self.message.red().bold().to_string());
            }
        }
        if let Some(ref detail) = self.detail {
            for line in detail.lines() {
                println!("           {}", line.bright_black());
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    ModuleStart(String),
    ModuleProgress(String, String),
    Finding(Finding),
    ModuleDone(String, std::time::Duration),
}

pub type Sender = mpsc::Sender<ScanEvent>;

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub version: String,
    pub scan_mode: String,
    pub hostname: String,
    pub username: String,
    pub platform: String,
    pub timestamp: String,
    pub duration_secs: f64,
    pub findings: Vec<Finding>,
}

impl ScanReport {
    pub fn new(scan_mode: String, hostname: String, username: String) -> Self {
        ScanReport {
            version: "1.0.0".to_string(),
            scan_mode,
            hostname,
            username,
            platform: std::env::consts::OS.to_string(),
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            duration_secs: 0.0,
            findings: Vec::new(),
        }
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

    pub fn print_summary(&self) {
        let (safe, info, warn, danger) = self.count_by_severity();
        let total = safe + info + warn + danger;

        println!();
        println!("  {} {}   {} {}   {} {}   {} {}   {} {}",
            "Total:".bold(), total.to_string().white().bold(),
            "DANGER:".red().bold(), danger.to_string().red().bold(),
            "WARNING:".yellow().bold(), warn.to_string().yellow().bold(),
            "INFO:".blue().bold(), info,
            "SAFE:".green().bold(), safe);
        println!();

        if danger > 0 {
            println!("  {}", "!! CRITICAL: Dangerous findings detected! Investigate immediately.".red().bold());
        } else if warn > 0 {
            println!("  {}", "!! Warnings found. Review recommended.".yellow().bold());
        } else {
            println!("  {}", ">> System appears clean. No threats detected.".green().bold());
        }
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let mut f = File::create(path)?;

        writeln!(f, "╔══════════════════════════════════════════════════════════════════════╗")?;
        writeln!(f, "║         Narayanastra v1.0.0 — Deep Scan Report | CyberHX            ║")?;
        writeln!(f, "╚══════════════════════════════════════════════════════════════════════╝")?;
        writeln!(f)?;
        writeln!(f, "  Scan Mode : {}", self.scan_mode)?;
        writeln!(f, "  Hostname  : {}", self.hostname)?;
        writeln!(f, "  Username  : {}", self.username)?;
        writeln!(f, "  Platform  : {}", self.platform)?;
        writeln!(f, "  Timestamp : {}", self.timestamp)?;
        writeln!(f, "  Duration  : {:.2}s", self.duration_secs)?;
        writeln!(f)?;

        // Group findings by module
        let modules = ["ROOTKIT", "PROCESS", "NETWORK", "FILES", "MEMORY", "LOGS", "ANTIFOR", "OFFLINE", "WINDOWS"];
        for module in &modules {
            let module_findings: Vec<&Finding> = self.findings.iter()
                .filter(|fi| fi.module == *module)
                .collect();

            if module_findings.is_empty() {
                continue;
            }

            writeln!(f, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
            writeln!(f, "  MODULE: {}", module)?;
            writeln!(f, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;

            for finding in &module_findings {
                writeln!(f, "  {} [{}] {}", finding.severity, finding.category, finding.message)?;
                if let Some(ref detail) = finding.detail {
                    for line in detail.lines() {
                        writeln!(f, "           {}", line)?;
                    }
                }
            }
            writeln!(f)?;
        }

        let (safe, info, warn, danger) = self.count_by_severity();
        let total = safe + info + warn + danger;
        writeln!(f, "══════════════════════════════════════════════════════════════════════")?;
        writeln!(f, "  SUMMARY")?;
        writeln!(f, "══════════════════════════════════════════════════════════════════════")?;
        writeln!(f, "  Total: {}  |  DANGER: {}  |  WARNING: {}  |  INFO: {}  |  SAFE: {}", total, danger, warn, info, safe)?;
        writeln!(f)?;
        if danger > 0 {
            writeln!(f, "  !! CRITICAL: Dangerous findings detected!")?;
        } else if warn > 0 {
            writeln!(f, "  !! Warnings found. Review recommended.")?;
        } else {
            writeln!(f, "  >> System appears clean.")?;
        }
        writeln!(f)?;
        writeln!(f, "══════════════════════════════════════════════════════════════════════")?;
        writeln!(f, "  Narayanastra v1.0.0 | {}", self.timestamp)?;
        writeln!(f, "  Built by Kushagra Dwivedi | CyberHX")?;
        writeln!(f, "══════════════════════════════════════════════════════════════════════")?;

        // JSON report
        let json_path = path.replace(".txt", ".json");
        if let Ok(json) = serde_json::to_string_pretty(self) {
            if let Ok(mut jf) = File::create(&json_path) {
                let _ = jf.write_all(json.as_bytes());
            }
        }

        Ok(())
    }
}
