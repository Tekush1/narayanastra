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
  <img src="https://img.shields.io/badge/version-2.0.0-cyan?style=flat-square" />
</p>

---

**Narayanastra** is a post-compromise scanner that hunts rootkits, backdoors and silent persistence on systems that may already be owned. It is written in Rust, runs 12 detection modules in parallel with live streaming output, and was built on one rule: **never trust the host you are scanning**.

> *In Hindu mythology, the Narayanastra is Lord Vishnu's unstoppable divine weapon — the more you resist, the more powerful it becomes. A rootkit that hides only makes Narayanastra hunt harder.*

## Why Narayanastra?

- **Cross-view detection** — compares what the kernel *does* (syscall probes, `bind()`, netlink) with what it *reports* (`/proc`, module lists). Hidden processes, sockets, modules and eBPF programs show up as disagreements.
- **Doesn't trust the compromised host** — no shelling out to `ps`/`ss`/`find`; `/proc` is listed with raw `getdents64` syscalls (immune to `LD_PRELOAD` readdir hooks); the few external tools it still uses (dpkg, rpm, journalctl…) run by absolute path, only if root-owned, with a clean environment.
- **Detects attacks that blind syscall-based EDRs** — io_uring rootkits (e.g. *Curing*), eBPF rootkits that hide from `bpf()`, ftrace hooks, syscall-table hooks.
- **Package-aware, low false positives** — SUID files, PAM modules, kernel modules and persistence files are judged by package ownership and checksums (dpkg, rpm, pacman, apk), not by name lists.
- **Offline forensic mode** — scan a mounted disk where the rootkit isn't running. The disk is treated as hostile input: symlinks are re-rooted inside the target, reads are size-capped, initramfs images are parsed in memory.
- **Baselines and live-vs-offline crossdiff** — HMAC-signed integrity baselines, and a diff that shows what the running OS hid compared to its own disk.
- **Reports people can use** — text, JSON, NDJSON (SIEM), SARIF (GitHub code scanning), self-contained HTML, MITRE ATT&CK ids on every finding, evidence collection, webhooks.
- **Single static binary** (~3.5 MB musl build) — drop it on the box and run.

## Installation

### Pre-built (recommended)

Download from [Releases](https://github.com/Tekush1/narayanastra/releases): `narayanastra-linux-x86_64`, `narayanastra-linux-aarch64`, `narayanastra-windows-x86_64.exe` and `SHA256SUMS`. The Linux builds are **static musl binaries** — `LD_PRELOAD` and `/etc/ld.so.preload` userland rootkits cannot inject into them.

### From source

```bash
git clone https://github.com/Tekush1/narayanastra.git
cd narayanastra

# static, injection-proof build (recommended for incident response)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
sudo cp target/x86_64-unknown-linux-musl/release/narayanastra /usr/local/bin/

# or a normal build
cargo build --release
```

### Cross-compile for Windows

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install gcc-mingw-w64-x86-64
cargo build --release --target x86_64-pc-windows-gnu
```

## Usage

```bash
narayanastra                                  # quick scan (no root needed, root recommended)
sudo narayanastra --full                      # deep scan: PID sweep, bind probe, full package verify
sudo narayanastra -f --watch 60               # re-scan every 60s, alert only on new findings
sudo narayanastra --offline /mnt/target       # offline forensic scan of a mounted disk
sudo narayanastra --container web1            # scan a running container's filesystem
narayanastra --remote ubuntu@server -f        # upload, scan over SSH, download reports, clean up

sudo narayanastra --format html,sarif,ndjson  # extra report formats (text + json always written)
sudo narayanastra --modules rootkit,ebpf      # run a subset of modules
sudo narayanastra --collect                   # copy flagged binaries/scripts into evidence/ with sha256
sudo narayanastra --hashdb trusted.json       # verify files against a trusted path->sha256 database
sudo narayanastra --webhook https://hooks...  # push DANGER findings to Slack/Discord

# integrity baselines
sudo narayanastra baseline save base.json --key-file /root/nst.key
sudo narayanastra baseline diff base.json --key-file /root/nst.key

# live vs offline: what is the running OS hiding?
sudo narayanastra baseline save live.json                       # on the running system
sudo narayanastra baseline save disk.json --root /mnt/target    # from a USB boot
narayanastra crossdiff --live live.json --offline disk.json      # writes crossdiff.md + .csv
```

Reports go to a new private directory `./narayanastra-<host>-<timestamp>/` (or `-o DIR`). Files are created with `O_EXCL|O_NOFOLLOW`, so running as root in `/tmp` can't be abused with planted symlinks.

**Exit codes:** `0` clean · `1` warnings · `2` danger · `3` scanner error / incomplete scan.

## Modules

### Linux (12 parallel modules)

| Module | What it detects |
|--------|-----------------|
| **ROOTKIT** | Hidden processes by PID brute force (`kill(0)`, `getpgid`, `getsid`, `sched_getaffinity`) vs raw `/proc` listing · modules hidden from `/proc/modules` (sysfs `initstate`, kallsyms owners) · memfd/deleted executables · `LD_PRELOAD`/`LD_AUDIT` in every process · mounts over `/proc/<pid>` · rootkit signatures (separate category) |
| **PROCESS** | Shells with stdin/stdout wired to sockets · shells spawned by web servers / service accounts · reverse-shell command regexes · crypto miners · user processes disguised as kernel threads (`[kworker/0:1]` with an exe) · daemon name spoofing (merged-/usr and package aware) · temp-dir execution · obfuscated command lines |
| **NETWORK** | netlink `sock_diag` vs `/proc/net/{tcp,udp}{,6}` in both directions (catches `tcp4_seq_show` hooks) · `bind()` probe of all 65535 TCP/UDP ports for listeners hidden from every view (`--full`) · listeners owned by temp/deleted binaries · C2 ports · IPv4/IPv6/CIDR threat feed · promiscuous NICs · raw & AF_PACKET sockets (BPFDoor-style) |
| **FILES** | SUID/SGID by package ownership (temp/home locations always flagged) · native dpkg md5 verification (dpkg diversions & conffiles aware), rpm/pacman/apk verification · executables in `/dev/shm` · world-writable sensitive files · immutable/append-only flags via `FS_IOC_GETFLAGS` |
| **MEMORY** | RWX regions per process (JIT-aware per region, daemons never excused) · executable memfd mappings · code from temp/hidden/deleted libraries · exe vs argv[0] mismatches |
| **LOGS** | Brute force and successful logins from brute-forcing IPs · real timestamp parsing (no false alarms at month boundaries) · native wtmp/btmp parsing (zeroed records, cut records) · history evasion for every user · `journalctl --verify` |
| **ANTIFOR** | Timestomping · deceptive names (`...`, invisible/bidi Unicode) · hidden executables · log symlinks/ownership · unpackaged PAM modules on every architecture · `pam_permit`/`pam_exec` backdoors · startup-hook env vars |
| **PERSIST** | uid-0 duplicates, empty passwords, revived system accounts · sudoers · sshd_config · authorized_keys of every user · system/user crontabs & at jobs · systemd units, timers, drop-ins, generators · shell rc/profile/motd/rc.local · `ld.so.preload`/`ld.so.conf.d` · udev `RUN+=` · APT/DNF hooks · XDG autostart · kernel module autoload |
| **IOURING** | Processes owning io_uring instances (`/proc/*/fdinfo`), SQPOLL kernel threads, and what else they do (remote sockets, socket stdio, odd binaries) — the syscall-less channel used by io_uring rootkits |
| **EBPF** | Programs from four views — `bpf()` enumeration, `/proc/*/fdinfo`, kallsyms JIT images, `/sys/fs/bpf` pins — anything missing from `bpf()` is hidden · helper-call analysis (`bpf_probe_write_user`, `bpf_override_return`, `bpf_send_signal`) |
| **KHOOKS** | ftrace hooks on sensitive kernel functions · kprobes · syscall table entries outside kernel text (read via `/proc/kcore`) · kernel log evidence of out-of-tree/unsigned module loads · taint, lockdown, signature enforcement |
| **CONTAINER** | Running containers (docker, containerd, podman, CRI-O, k8s, LXC) · privileged containers · host namespace sharing · mounted runtime sockets · host root bind mounts |

### Windows (7 checks via PowerShell)

| Check | What it detects |
|-------|-----------------|
| **Persistence** | Run keys · scheduled tasks judged by their action (the Author field is spoofable) · services from temp/user dirs · unquoted service paths |
| **DLL Injection** | AppInit_DLLs · IFEO debugger hijack · KnownDLLs |
| **Processes** | Temp-dir execution · encoded/bypass PowerShell |
| **Network** | C2 ports · disabled firewall profiles |
| **Credentials** | Admins · blank passwords · RDP · WinRM |
| **Drivers** | Drivers from unusual paths · running drivers without a valid Authenticode signature · known rootkit driver names |
| **Event Logs** | Security log cleared (1102) · disabled logs · brute force (4625) · Defender disabled |

PowerShell is always launched by its absolute `System32` path.

## Modes

### Normal / Full
One-shot scan. `--full` turns on the expensive checks: whole-PID-space sweep, `bind()` probe, recursive walks and verification of every packaged file.

### Watch (`--watch N`)
The first scan prints everything; later scans alert only on **new** Warning/Danger findings (stable finding ids, so changing counts don't re-alert). On Ctrl+C the combined report is written.

### Offline (`--offline /mnt/target`) — Linux
Boot a live USB, mount the suspect disk, scan it while the rootkit is not running:
- Kernel modules on disk — known names, and a hook-indicator content scan of every unpackaged module (`.ko`, `.ko.xz`, `.ko.zst`)
- Package verification against the target's database — or, better, a trusted `--hashdb` (an attacker with root can edit the target's own checksum database)
- The full persistence sweep, PAM checks, bootloader/GRUB parameters
- Initramfs images parsed in memory (microcode + compressed cpio), scanning for rootkit modules, backdoored scripts and `ld.so.preload`
- SUID files and binaries in temp/home dirs, wiped or redirected logs

### Container (`--container ID|PID`)
Runs the offline checks against a running container's root filesystem.

### Remote (`--remote user@host`)
Checks the remote architecture, uploads the binary to a fresh `mktemp -d`, runs it, downloads the report directory and removes everything.

## How It Works

### Cross-view detection
A rootkit has to lie to *someone*. Narayanastra asks the same question through different kernel paths and reports disagreements:

| Question | View A | View B |
|---|---|---|
| Which processes exist? | raw `getdents64` on `/proc` | `kill(pid, 0)` / `getpgid` / `getsid` for every PID |
| Which sockets exist? | `/proc/net/*` (seq_file) | netlink `sock_diag`, and `bind()` on every port |
| Which modules are loaded? | `/proc/modules` | `/sys/module/*/initstate`, kallsyms owners, kernel log |
| Which eBPF programs exist? | `bpf(BPF_PROG_GET_NEXT_ID)` | fdinfo, kallsyms JIT symbols, `/sys/fs/bpf` pins |
| What is on disk? | live baseline | offline baseline of the same disk (`crossdiff`) |

### Behaviour over names
- **Reverse shells:** a shell whose stdin/stdout is a socket is a reverse shell, whatever it's called.
- **JIT memory:** RWX is excused only in processes that really embed a JIT (V8, JVM, SpiderMonkey, LuaJIT, …) — never in sshd, systemd, cron or bash.
- **Virtual NICs:** promiscuous mode is judged by sysfs properties (bridge port, tun/tap, veth peer), not interface names.
- **Packages:** "is this file shipped and unmodified?" replaces hardcoded whitelists for SUID files, PAM modules, kernel modules and persistence files.

### Architecture

```
main ─┬─ spawn 12 module threads ──► ScanEvent (Start / Progress / Finding / Done) over mpsc
      │                                   │
      │   rx loop: live output, collect ◄─┘   (a crashed module is reported, never hidden)
      ▼
  ScanReport ─► dedup by stable id ─► report.txt / .json / .ndjson / .sarif / .html
                                   └► evidence/ + manifest.json   (--collect)
```

## Threat Feed

Put known C2 IPs or CIDR ranges (IPv4/IPv6, one per line, `#` comments) in `threat_feeds/c2_ips.txt` next to the binary, `/etc/narayanastra/c2_ips.txt`, or pass `--feed FILE`.

## Output

- **[DANGER]** — active compromise indicators (hidden processes, syscall hooks, reverse shells, C2 traffic, backdoored PAM)
- **[WARNING]** — suspicious, needs investigation
- **[INFO]** — context (inventories, posture)
- **[SAFE]** — a check ran and found nothing

Every finding carries a MITRE ATT&CK technique id where one applies.

## Limitations

No user-space scanner can fully defeat a kernel rootkit that controls every view it can ask. Narayanastra makes hiding expensive — the rootkit must lie consistently through `/proc`, netlink, `bind()`, `bpf()`, kallsyms, kcore and the disk — and offline mode removes the rootkit from the picture. Some checks need root, tracefs or an unlocked `/proc/kcore`; when a view is unavailable the report says so instead of claiming the system is clean.

## Development

```bash
cargo test --release                                   # unit tests (fixtures, no live system needed)
cargo clippy --release --all-targets -- -D warnings
cargo fmt --check
```

## Disclaimer

This tool is for **authorized security assessments, incident response and system administration**. Only use it on systems you own or are explicitly authorized to scan. The authors are not responsible for misuse.

## License

MIT License — see [LICENSE](LICENSE)

## Author

**Kushagra Dwivedi** — [CyberHX](https://cyberhx.com) · [GitHub](https://github.com/Tekush1)

---

<p align="center">
  <em>जितना छुपेगा, उतना ढूंढेगा — The more it hides, the harder it hunts.</em>
</p>
