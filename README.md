<p align="center">
  <h1 align="center">नारायणास्त्र — Narayanastra</h1>
  <p align="center"><strong>Vishnu's Ultimate Weapon Against Silent Compromise</strong></p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#usage">Usage</a> •
    <a href="#modules">Modules</a> •
    <a href="#modes">Modes</a> •
    <a href="#how-it-works">How It Works</a>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/language-Rust-orange?style=flat-square" />
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" />
  <img src="https://img.shields.io/badge/version-1.0.0-cyan?style=flat-square" />
</p>

---

**Narayanastra** is a post-compromise security scanner that detects rootkits, backdoors, and silent threats on systems. Built in Rust for speed and safety — 7 deep-scan modules running in parallel with real-time streaming output.

> *In Hindu mythology, the Narayanastra is Lord Vishnu's unstoppable divine weapon — the more you resist, the more powerful it becomes. A rootkit that hides only makes Narayanastra hunt harder.*

## Why Narayanastra?

- **Post-compromise detection** — not antivirus, this finds threats that are already inside
- **Behavior-based detection** — no hardcoded whitelists, detects by what things DO not what they're named
- **Zero false positives** — rigorously tested on clean systems
- **Offline forensic mode** — boot from USB, scan a mounted disk where rootkits CANNOT hide
- **Cross-platform** — Linux (7 modules) + Windows (7 checks via PowerShell)
- **~1MB binary** — no dependencies, no runtime, just drop and run

## Installation

### From Source (Recommended)

```bash
# Clone
git clone https://github.com/CyberHX/narayanastra.git
cd narayanastra

# Build
cargo build --release

# Install
sudo cp target/release/narayanastra /usr/local/bin/
```

### Cross-compile for Windows

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu
# Binary: target/x86_64-pc-windows-gnu/release/narayanastra.exe
```

## Usage

```bash
# Quick scan (no root needed)
narayanastra

# Full deep scan (root recommended)
sudo narayanastra --full

# Continuous monitoring — rescan every 30 seconds
narayanastra --watch 30

# Full scan + watch mode
sudo narayanastra -f --watch 60

# Offline forensic scan (USB boot)
sudo narayanastra --offline /mnt/target

# Remote server scan via SSH
narayanastra --remote root@54.23.11.90
narayanastra --remote ubuntu@myserver --full
```

## Modules

### Linux (7 Parallel Modules)

| Module | What It Scans |
|--------|--------------|
| **ROOTKIT** | Hidden PIDs (/proc vs ps), deleted binaries, LD_PRELOAD injection, hidden kernel modules, known rootkit names, kernel taint flags |
| **PROCESS** | Reverse shell patterns (shell spawned by web server, /dev/tcp), crypto miners (stratum, pool connections), process name spoofing, temp dir execution |
| **NETWORK** | Hidden ports (ss vs /proc/net/tcp), suspicious listening ports, outbound to C2 ports, promiscuous NICs (behavior-based bridge detection), raw sockets, C2 IP threat feed matching |
| **FILES** | SUID/SGID anomalies, package integrity (dpkg --verify), /dev/shm executables, world-writable sensitive files, immutable file abuse, cron/shell persistence |
| **MEMORY** | RWX anonymous mappings (with JIT-aware filtering for Chrome/Node/Electron), injected libraries from temp dirs, /dev/shm ELF/shellcode, process hollowing |
| **LOGS** | Brute force detection (auth.log), log gaps/timestamp anomalies, shell history evasion (/dev/null symlinks), wtmp/btmp analysis, journald security events |
| **ANTIFOR** | Timestomping (future-dated/pre-2000 binaries), hidden files with ELF content, log wiping, PAM backdoors, suspicious environment variables (LD_PRELOAD, BASH_ENV), rootkit artifacts on disk |

### Windows (7 Checks via PowerShell)

| Check | What It Scans |
|-------|--------------|
| **Persistence** | Registry Run keys (HKLM/HKCU), scheduled tasks (non-Microsoft), services from temp dirs, unquoted service paths |
| **DLL Injection** | AppInit_DLLs, Image File Execution Options debugger hijack, KnownDLLs override |
| **Processes** | Temp dir execution, PowerShell with suspicious args (-enc, bypass, downloadstring, hidden) |
| **Network** | Connections to C2 ports (4444, 1337, 31337...), disabled firewall profiles |
| **Credentials** | Admin accounts, blank passwords, RDP status, WinRM status |
| **Drivers** | Drivers from unusual paths, known rootkit driver names |
| **Event Logs** | Security log cleared (1102), disabled logs, brute force (4625), Defender disabled |

## Modes

### Normal Mode
One-shot scan with full output. Reports saved as `scan_report.txt` and `scan_report.json`.

### Watch Mode (`--watch N`)
Continuous monitoring. First scan shows full results, subsequent scans only alert on **NEW** Warning/Danger findings. Deduplication prevents alert fatigue. Clean Ctrl+C shutdown.

### Offline Mode (`--offline /mnt/target`)
**Linux only.** Boot from a USB/live disk, mount the target drive, and scan it offline. The rootkit is not running so it **cannot hide**:
- Kernel module scanning for rootkit signatures and hooking patterns
- Binary integrity via target's own dpkg database
- Persistence mechanisms (cron, systemd, PAM backdoors, SSH keys)
- Initramfs unpacking and scanning for embedded rootkits
- Bootloader (GRUB) integrity checks
- Hidden files/SUID binaries in temp directories
- Log evidence (wiped logs, wrong ownership)

### Remote Mode (`--remote user@host`)
SSH into a remote server, upload the binary, run scan, pull reports back, clean up. One command.

## How It Works

### Behavior-Based Detection (No Whitelists)

Narayanastra doesn't maintain lists of "known good" applications. Instead, it detects by **behavior**:

- **JIT Detection**: Instead of whitelisting Chrome/Node/Electron, it checks if a process has loaded JIT engine libraries (libv8, libjvm, etc.) or has V8 symbols in its binary. Any app with a JIT engine gets RWX memory — that's normal. A process WITHOUT a JIT engine that has RWX anonymous memory is suspicious.

- **Virtual NIC Detection**: Instead of whitelisting "docker0", "veth*", etc., it checks `/sys/class/net/{iface}/master` (bridge member), `/sys/class/net/{iface}/bridge` (is a bridge), device type (65534 = virtual), and iflink vs ifindex (veth pair). Works for any container runtime, VM, or overlay network.

- **Hidden File Detection**: Instead of whitelisting ".config", ".local", etc., it checks the **content** — hidden files containing ELF binaries, PE executables, or suspicious scripts get flagged. A hidden config dir with text files is ignored.

### Architecture

```
main() → spawn 7 threads → each module sends ScanEvent via mpsc channel
       ↓                    ↓
       rx loop              ModuleStart / ModuleProgress / Finding / ModuleDone
       ↓
       Real-time display + collect findings
       ↓
       ScanReport → scan_report.txt + scan_report.json
```

## Threat Feed

Place known C2 IPs in `threat_feeds/c2_ips.txt` (one per line). The network module matches all active connections against this list.

## Output

Findings are categorized by severity:
- **[DANGER]** — Active compromise indicators (rootkit modules, reverse shells, C2 connections)
- **[WARNING]** — Suspicious activity requiring investigation
- **[INFO]** — Informational (process counts, connection counts)
- **[SAFE]** — Verified clean checks

Reports are saved in both human-readable text and machine-parseable JSON formats.

## Requirements

- **Linux**: Any modern Linux (kernel 3.x+). Root/sudo recommended for full scan.
- **Windows**: Windows 10/11, Server 2016+. Admin recommended. PowerShell required.
- **Build**: Rust 1.70+ and Cargo

## Disclaimer

This tool is designed for **authorized security assessments, incident response, and system administration**. Only use it on systems you own or have explicit authorization to scan. The authors are not responsible for misuse.

## License

MIT License — see [LICENSE](LICENSE)

## Author

**Kushagra Dwivedi** — [CyberHX](https://cyberhx.com)

---

<p align="center">
  <em>जितना छुपेगा, उतना ढूंढेगा — The more it hides, the harder it hunts.</em>
</p>
