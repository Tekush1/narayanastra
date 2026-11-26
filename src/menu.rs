//! Interactive start menu, shown when the scanner is started from a terminal
//! without any options. Every choice maps onto the normal command-line flags,
//! so scripted use is unaffected.

use crate::Opts;
use colored::*;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

struct Button {
    key: char,
    title: &'static str,
    detail: &'static str,
    colour: Color,
}

const BUTTON_WIDTH: usize = 36;
/// Width of the two-button grid: two buttons, their shadows and the gap.
const GRID_WIDTH: usize = 2 * (BUTTON_WIDTH + 1) + 3;

static INDENT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(2);

fn pad() -> String {
    " ".repeat(INDENT.load(std::sync::atomic::Ordering::Relaxed))
}

const MAIN: [Button; 4] = [
    Button { key: '1', title: "QUICK SCAN", detail: "Fast check of this machine", colour: Color::BrightGreen },
    Button { key: '2', title: "DEEP SCAN", detail: "Every process, port and file", colour: Color::BrightCyan },
    Button { key: '3', title: "OFFLINE DISK", detail: "Scan a mounted disk or image", colour: Color::BrightYellow },
    Button { key: '4', title: "MORE OPTIONS", detail: "Watch, container, remote, checks", colour: Color::BrightMagenta },
];

const MORE: [Button; 4] = [
    Button { key: '1', title: "WATCH MODE", detail: "Keep scanning, alert on new", colour: Color::BrightGreen },
    Button { key: '2', title: "CONTAINER", detail: "Scan a running container", colour: Color::BrightCyan },
    Button { key: '3', title: "REMOTE SERVER", detail: "Scan another machine over SSH", colour: Color::BrightYellow },
    Button { key: '4', title: "PICK CHECKS", detail: "Choose which modules to run", colour: Color::BrightMagenta },
];

const MODULES: [&str; 12] = ["rootkit", "process", "network", "files", "memory", "logs", "antifor", "persist", "iouring", "ebpf", "khooks", "container"];

/// One text row of a button: coloured fill plus a grey shadow on the right.
fn row(b: &Button, text: &str, bold: bool) -> String {
    let text: String = text.chars().take(BUTTON_WIDTH).collect();
    let padded = format!("{:<width$}", text, width = BUTTON_WIDTH);
    let face = if bold { padded.black().bold().on_color(b.colour) } else { padded.black().on_color(b.colour) };
    format!("{}{}", face, "▌".bright_black())
}

fn draw(buttons: &[Button; 4]) {
    for pair in buttons.chunks(2) {
        let lines = |b: &Button| {
            [
                row(b, "", false),
                row(b, &format!("  {}  {}", b.key, b.title), true),
                row(b, &format!("    {}", b.detail), false),
                row(b, "", false),
                format!(" {}", "▀".repeat(BUTTON_WIDTH).bright_black()),
            ]
        };
        let (left, right) = (lines(&pair[0]), lines(&pair[1]));
        for (l, r) in left.iter().zip(right.iter()) {
            println!("{}{}   {}", pad(), l, r);
        }
    }
}

fn ask(prompt: &str) -> Option<String> {
    print!("{}{} {} ", pad(), "❯".bright_green().bold(), prompt.bold());
    io::stdout().flush().ok();
    let mut line = String::new();
    match io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

/// Ask until the answer is one of `valid` (empty input picks `default`).
fn choose(prompt: &str, valid: &str, default: char) -> Option<char> {
    loop {
        let answer = ask(prompt)?;
        let c = answer.chars().next().unwrap_or(default);
        if answer.chars().count() <= 1 && valid.contains(c) {
            return Some(c);
        }
        println!("{}{}", pad(), format!("Please type one of: {}", valid.chars().map(String::from).collect::<Vec<_>>().join(", ")).yellow());
    }
}

fn ask_required(prompt: &str) -> Option<String> {
    loop {
        let answer = ask(prompt)?;
        if !answer.is_empty() {
            return Some(answer);
        }
    }
}

fn heading(text: &str) {
    println!();
    println!("{}{}", pad(), text.bright_white().bold());
    println!();
}

/// Show the menu and fill `opts` from the answers. Returns false if the user quit.
pub fn run(opts: &mut Opts, logo_width: usize) -> bool {
    INDENT.store(2 + logo_width.saturating_sub(GRID_WIDTH) / 2, std::sync::atomic::Ordering::Relaxed);
    heading("What do you want to scan?");
    draw(&MAIN);
    println!("{}{}", pad(), "0  Exit".dimmed());
    println!();
    let pick = match choose("Choose 1-4 (Enter = 1):", "01234", '1') {
        Some(c) => c,
        None => return false,
    };
    match pick {
        '0' => return false,
        '2' => opts.full = true,
        '3' => match ask_path("Path of the mounted disk (e.g. /mnt/disk):") {
            Some(p) => opts.offline = Some(p),
            None => return false,
        },
        '4' if !more(opts) => return false,
        _ => {}
    }

    heading("Report");
    println!(
        "{}{}  Text + JSON      {}  + HTML page      {}  Everything (adds SARIF, NDJSON)",
        pad(),
        "1".bright_green().bold(),
        "2".bright_cyan().bold(),
        "3".bright_yellow().bold()
    );
    println!();
    match choose("Choose 1-3 (Enter = 1):", "123", '1') {
        Some('2') => opts.format = vec!["html".into()],
        Some('3') => opts.format = vec!["html".into(), "sarif".into(), "ndjson".into()],
        Some(_) => {}
        None => return false,
    }
    match choose("Save copies of suspicious files as evidence? [y/N]:", "yYnN", 'n') {
        Some('y') | Some('Y') => opts.collect = true,
        Some(_) => {}
        None => return false,
    }

    println!();
    println!("{}{} {}", pad(), "Tip: next time run it directly with".dimmed(), equivalent_command(opts).bright_white());
    println!();
    true
}

fn more(opts: &mut Opts) -> bool {
    heading("More options");
    draw(&MORE);
    println!("{}{}", pad(), "0  Exit".dimmed());
    println!();
    match choose("Choose 1-4:", "01234", '1') {
        Some('1') => {
            let secs = ask("Re-scan every how many seconds? (Enter = 60):").map(|s| s.parse::<u64>().unwrap_or(60).max(5));
            match secs {
                Some(s) => opts.watch = Some(s),
                None => return false,
            }
        }
        Some('2') => match ask_required("Container name, ID or PID:") {
            Some(c) => opts.container = Some(c),
            None => return false,
        },
        Some('3') => match ask_required("Server to scan (user@host):") {
            Some(h) => opts.remote = Some(h),
            None => return false,
        },
        Some('4') => {
            println!();
            for (i, m) in MODULES.iter().enumerate() {
                print!("{}{:>2}  {:<10}", if i % 4 == 0 { pad() } else { "  ".into() }, (i + 1).to_string().bright_cyan().bold(), m);
                if i % 4 == 3 {
                    println!();
                }
            }
            println!();
            let answer = match ask("Numbers separated by commas (e.g. 1,2,10):") {
                Some(a) => a,
                None => return false,
            };
            opts.modules = answer
                .split(',')
                .filter_map(|n| n.trim().parse::<usize>().ok())
                .filter_map(|n| MODULES.get(n.wrapping_sub(1)))
                .map(|m| m.to_string())
                .collect();
        }
        _ => return false,
    }
    true
}

fn ask_path(prompt: &str) -> Option<PathBuf> {
    loop {
        let p = PathBuf::from(ask_required(prompt)?);
        if p.is_dir() {
            return Some(p);
        }
        println!("{}{}", pad(), "That folder does not exist. Mount the disk first, then give its folder.".yellow());
    }
}

fn equivalent_command(opts: &Opts) -> String {
    let mut cmd = vec!["sudo narayanastra".to_string()];
    if opts.full {
        cmd.push("--full".into());
    }
    if let Some(p) = &opts.offline {
        cmd.push(format!("--offline {}", p.display()));
    }
    if let Some(s) = opts.watch {
        cmd.push(format!("--watch {}", s));
    }
    if let Some(c) = &opts.container {
        cmd.push(format!("--container {}", c));
    }
    if let Some(h) = &opts.remote {
        cmd.push(format!("--remote {}", h));
    }
    if !opts.modules.is_empty() {
        cmd.push(format!("--modules {}", opts.modules.join(",")));
    }
    if !opts.format.is_empty() {
        cmd.push(format!("--format {}", opts.format.join(",")));
    }
    if opts.collect {
        cmd.push("--collect".into());
    }
    cmd.join(" ")
}
