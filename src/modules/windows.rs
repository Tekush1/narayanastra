use crate::report::{Finding, ScanEvent, Sender, Severity};
use std::process::Command;
use std::time::Instant;

const MODULE: &str = "WINDOWS";

fn send(tx: &Sender, finding: Finding) {
    let _ = tx.send(ScanEvent::Finding(finding));
}

fn progress(tx: &Sender, msg: &str) {
    let _ = tx.send(ScanEvent::ModuleProgress(MODULE.to_string(), msg.to_string()));
}

fn run_ps(script: &str) -> Option<String> {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  1. PERSISTENCE — Registry Run Keys, Scheduled Tasks, Services
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn persistence_scan(tx: &Sender) {
    progress(tx, "Scanning Windows persistence mechanisms...");

    // Registry Run keys
    let run_keys = [
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ];

    for key in &run_keys {
        let script = format!(
            "Get-ItemProperty '{}' -ErrorAction SilentlyContinue | ForEach-Object {{ $_.PSObject.Properties | Where-Object {{ $_.Name -notlike 'PS*' }} | ForEach-Object {{ Write-Output \"$($_.Name)=$($_.Value)\" }} }}",
            key
        );
        if let Some(output) = run_ps(&script) {
            let suspicious_patterns = ["powershell", "cmd /c", "wscript", "cscript",
                "mshta", "rundll32", "regsvr32", "%temp%", "%appdata%",
                "\\temp\\", "\\tmp\\", "-enc", "-e ", "bypass", "hidden",
                "downloadstring", "invoke-expression", "iex"];
            for line in output.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() { continue; }
                let lower = trimmed.to_lowercase();
                for pat in &suspicious_patterns {
                    if lower.contains(pat) {
                        send(tx, Finding::new(Severity::Warning, MODULE, "Registry Run",
                            &format!("Suspicious autorun in {}", key))
                            .with_detail(trimmed));
                        break;
                    }
                }
            }
        }
    }

    // Scheduled Tasks — non-Microsoft
    progress(tx, "Checking scheduled tasks...");
    let task_script = r#"Get-ScheduledTask | Where-Object { $_.Author -notlike '*Microsoft*' -and $_.State -ne 'Disabled' } | ForEach-Object { $actions = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }); Write-Output "$($_.TaskName)|$($_.Author)|$actions" }"#;
    if let Some(output) = run_ps(task_script) {
        let bad_patterns = ["powershell", "cmd /c", "wscript", "mshta",
            "\\temp\\", "\\tmp\\", "-enc", "bypass", "downloadstring"];
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let lower = trimmed.to_lowercase();
            for pat in &bad_patterns {
                if lower.contains(pat) {
                    let parts: Vec<&str> = trimmed.splitn(3, '|').collect();
                    let task_name = parts.first().unwrap_or(&"unknown");
                    send(tx, Finding::new(Severity::Warning, MODULE, "Scheduled Task",
                        &format!("Suspicious scheduled task: {}", task_name))
                        .with_detail(trimmed));
                    break;
                }
            }
        }
    }

    // Services running from unusual paths
    progress(tx, "Checking services...");
    let svc_script = r#"Get-WmiObject Win32_Service | Where-Object { $_.PathName -ne $null } | ForEach-Object { Write-Output "$($_.Name)|$($_.PathName)|$($_.StartMode)" }"#;
    if let Some(output) = run_ps(svc_script) {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let lower = trimmed.to_lowercase();
            // Services from temp/user dirs
            if lower.contains("\\temp\\") || lower.contains("\\tmp\\")
                || lower.contains("\\appdata\\") || lower.contains("\\downloads\\") {
                let parts: Vec<&str> = trimmed.splitn(3, '|').collect();
                let svc_name = parts.first().unwrap_or(&"unknown");
                send(tx, Finding::new(Severity::Warning, MODULE, "Suspicious Service",
                    &format!("Service running from unusual path: {}", svc_name))
                    .with_detail(trimmed));
            }
            // Unquoted service path with spaces — check the PATH portion, not the full line
            let parts: Vec<&str> = trimmed.splitn(3, '|').collect();
            if parts.len() >= 2 {
                let svc_path = parts[1].trim();
                let path_lower = svc_path.to_lowercase();
                if !svc_path.starts_with('"') && path_lower.contains(' ') && path_lower.contains("\\program") {
                    let svc_name = parts.first().unwrap_or(&"unknown");
                    send(tx, Finding::new(Severity::Warning, MODULE, "Unquoted Path",
                        &format!("Service with unquoted path (privesc risk): {}", svc_name))
                        .with_detail(svc_path));
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  2. DLL INJECTION DETECTION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn dll_injection_scan(tx: &Sender) {
    progress(tx, "Checking for DLL injection vectors...");

    // AppInit_DLLs — classic DLL injection
    let appinit_script = r#"
        $val = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'AppInit_DLLs' -ErrorAction SilentlyContinue).AppInit_DLLs;
        $load = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name 'LoadAppInit_DLLs' -ErrorAction SilentlyContinue).LoadAppInit_DLLs;
        if ($val -and $val -ne '') { Write-Output "AppInit_DLLs=$val|LoadEnabled=$load" }
    "#;
    if let Some(output) = run_ps(appinit_script) {
        let trimmed = output.trim();
        if !trimmed.is_empty() {
            send(tx, Finding::new(Severity::Danger, MODULE, "DLL Injection",
                "AppInit_DLLs is set — global DLL injection active")
                .with_detail(trimmed));
        }
    }

    // Image File Execution Options — debugger hijack
    let ifeo_script = r#"
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue |
        ForEach-Object { $dbg = (Get-ItemProperty $_.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue).Debugger; if ($dbg) { Write-Output "$($_.PSChildName)|$dbg" } }
    "#;
    if let Some(output) = run_ps(ifeo_script) {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let parts: Vec<&str> = trimmed.splitn(2, '|').collect();
            let target = parts.first().unwrap_or(&"unknown");
            send(tx, Finding::new(Severity::Danger, MODULE, "IFEO Hijack",
                &format!("Image File Execution Options debugger set for: {}", target))
                .with_detail(trimmed));
        }
    }

    // Known DLLs override check
    let knowndlls_script = r#"
        $known = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' -ErrorAction SilentlyContinue;
        if ($known) { $known.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { Write-Output "$($_.Name)=$($_.Value)" } }
    "#;
    if let Some(output) = run_ps(knowndlls_script) {
        let standard_dlls = ["kernel32", "ntdll", "user32", "gdi32", "advapi32",
            "shell32", "ole32", "oleaut32", "msvcrt", "comdlg32", "comctl32",
            "shlwapi", "rpcrt4", "secur32", "ws2_32", "crypt32", "imm32",
            "setupapi", "cfgmgr32", "clbcatq", "difxapi", "iertutil",
            "imagehlp", "msctf", "normaliz", "nsi", "psapi", "shcore",
            "wldap32", "wow64", "wow64cpu", "wow64win"];
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let lower = trimmed.to_lowercase();
            if !standard_dlls.iter().any(|d| lower.contains(d)) {
                send(tx, Finding::new(Severity::Info, MODULE, "KnownDLLs",
                    &format!("Non-standard KnownDLLs entry: {}", trimmed)));
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  3. PROCESS SCAN
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn process_scan(tx: &Sender) {
    progress(tx, "Scanning running processes...");

    // Processes from temp/suspicious paths
    let proc_script = r#"Get-Process | Where-Object { $_.Path -ne $null } | ForEach-Object { Write-Output "$($_.Id)|$($_.Name)|$($_.Path)" }"#;
    if let Some(output) = run_ps(proc_script) {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let lower = trimmed.to_lowercase();

            if lower.contains("\\temp\\") || lower.contains("\\tmp\\")
                || lower.contains("\\downloads\\") || lower.contains("\\appdata\\local\\temp") {
                let parts: Vec<&str> = trimmed.splitn(3, '|').collect();
                let pid = parts.first().unwrap_or(&"?");
                let name = parts.get(1).unwrap_or(&"?");
                send(tx, Finding::new(Severity::Warning, MODULE, "Temp Process",
                    &format!("PID {} ({}) running from temp directory", pid, name))
                    .with_detail(parts.get(2).unwrap_or(&"")));
            }
        }
    }

    // PowerShell with suspicious arguments
    let ps_script = r#"Get-WmiObject Win32_Process | Where-Object { $_.Name -like '*powershell*' -or $_.Name -like '*pwsh*' } | ForEach-Object { Write-Output "$($_.ProcessId)|$($_.CommandLine)" }"#;
    if let Some(output) = run_ps(ps_script) {
        let bad = ["-enc", "-encodedcommand", "bypass", "hidden", "-w hidden",
            "downloadstring", "invoke-expression", "iex(", "iex (", "net.webclient",
            "invoke-webrequest", "start-bitstransfer"];
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let lower = trimmed.to_lowercase();
            for pat in &bad {
                if lower.contains(pat) {
                    let parts: Vec<&str> = trimmed.splitn(2, '|').collect();
                    let pid = parts.first().unwrap_or(&"?");
                    send(tx, Finding::new(Severity::Danger, MODULE, "Suspicious PS",
                        &format!("PowerShell PID {} with suspicious args", pid))
                        .with_detail(parts.get(1).unwrap_or(&"")));
                    break;
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  4. NETWORK SCAN
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn network_scan(tx: &Sender) {
    progress(tx, "Scanning network connections...");

    let net_script = r#"Get-NetTCPConnection -State Established,Listen 2>$null | ForEach-Object { $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name; Write-Output "$($_.State)|$($_.LocalPort)|$($_.RemoteAddress)|$($_.RemotePort)|$proc|$($_.OwningProcess)" }"#;
    if let Some(output) = run_ps(net_script) {
        let suspicious_ports = [4444, 1337, 31337, 8888, 9999, 5555, 1234, 6666, 7777, 4443, 8443, 13337];

        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let parts: Vec<&str> = trimmed.split('|').collect();
            if parts.len() < 6 { continue; }

            let state = parts[0];
            let local_port: u16 = parts[1].parse().unwrap_or(0);
            let remote_addr = parts[2];
            let remote_port: u16 = parts[3].parse().unwrap_or(0);
            let proc_name = parts[4];

            // Suspicious listening ports
            if state == "Listen" && suspicious_ports.contains(&local_port) {
                send(tx, Finding::new(Severity::Warning, MODULE, "Suspicious Port",
                    &format!("Listening on suspicious port {} ({})", local_port, proc_name)));
            }

            // Outbound to suspicious ports
            if state == "Established" && suspicious_ports.contains(&remote_port) {
                send(tx, Finding::new(Severity::Danger, MODULE, "C2 Connection",
                    &format!("Outbound to {}:{} by {} — possible C2", remote_addr, remote_port, proc_name)));
            }
        }
    }

    // Firewall rules — disabled or allow-all
    let fw_script = r#"Get-NetFirewallProfile | ForEach-Object { Write-Output "$($_.Name)|$($_.Enabled)" }"#;
    if let Some(output) = run_ps(fw_script) {
        for line in output.lines() {
            let parts: Vec<&str> = line.trim().split('|').collect();
            if parts.len() >= 2 && parts[1].trim().to_lowercase() == "false" {
                send(tx, Finding::new(Severity::Warning, MODULE, "Firewall",
                    &format!("Windows Firewall '{}' profile is DISABLED", parts[0])));
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  5. USER & CREDENTIAL SCAN
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn credential_scan(tx: &Sender) {
    progress(tx, "Checking user accounts and credentials...");

    // Hidden/new admin accounts
    let admin_script = r#"Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "$($_.Name)|$($_.ObjectClass)" }"#;
    if let Some(output) = run_ps(admin_script) {
        let mut admins = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                admins.push(trimmed.to_string());
            }
        }
        send(tx, Finding::new(Severity::Info, MODULE, "Admin Accounts",
            &format!("{} administrator account(s) found", admins.len()))
            .with_detail(&admins.join("\n")));
    }

    // Accounts with blank passwords
    let blank_pw_script = r#"Get-LocalUser | Where-Object { $_.PasswordRequired -eq $false -and $_.Enabled -eq $true } | ForEach-Object { Write-Output $_.Name }"#;
    if let Some(output) = run_ps(blank_pw_script) {
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                send(tx, Finding::new(Severity::Danger, MODULE, "Blank Password",
                    &format!("Enabled account with no password required: {}", trimmed)));
            }
        }
    }

    // RDP enabled check
    let rdp_script = r#"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections"#;
    if let Some(output) = run_ps(rdp_script) {
        if output.trim() == "0" {
            send(tx, Finding::new(Severity::Info, MODULE, "RDP",
                "Remote Desktop is ENABLED"));
        }
    }

    // WinRM enabled
    let winrm_script = r#"(Get-Service WinRM -ErrorAction SilentlyContinue).Status"#;
    if let Some(output) = run_ps(winrm_script) {
        if output.trim().to_lowercase() == "running" {
            send(tx, Finding::new(Severity::Info, MODULE, "WinRM",
                "WinRM service is running — remote management enabled"));
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  6. DRIVERS & ROOTKIT ARTIFACTS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn driver_scan(tx: &Sender) {
    progress(tx, "Checking kernel drivers...");

    // Unsigned drivers
    let drv_script = r#"Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -ne $null } | ForEach-Object { Write-Output "$($_.Name)|$($_.PathName)|$($_.Started)" }"#;
    if let Some(output) = run_ps(drv_script) {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }
            let lower = trimmed.to_lowercase();
            if lower.contains("\\temp\\") || lower.contains("\\tmp\\")
                || lower.contains("\\downloads\\") || lower.contains("\\appdata\\") {
                let parts: Vec<&str> = trimmed.splitn(3, '|').collect();
                let name = parts.first().unwrap_or(&"?");
                send(tx, Finding::new(Severity::Danger, MODULE, "Suspicious Driver",
                    &format!("Driver loaded from unusual path: {}", name))
                    .with_detail(trimmed));
            }
        }
    }

    // Check for known rootkit driver names
    let rootkit_drivers = ["fgexec", "beep", "null", "tdl", "max++", "rustock",
        "necurs", "zeroaccess", "alureon", "pihar", "sirefef"];
    let check_script = format!(
        "Get-WmiObject Win32_SystemDriver | Where-Object {{ $_.Started -eq $true }} | ForEach-Object {{ Write-Output $_.Name }}"
    );
    if let Some(output) = run_ps(&check_script) {
        for line in output.lines() {
            let name = line.trim().to_lowercase();
            for rk in &rootkit_drivers {
                if name.contains(rk) {
                    send(tx, Finding::new(Severity::Danger, MODULE, "Rootkit Driver",
                        &format!("Known rootkit driver name detected: {}", line.trim())));
                }
            }
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  7. EVENT LOG & ANTI-FORENSICS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn eventlog_scan(tx: &Sender) {
    progress(tx, "Checking Windows Event Logs...");

    // Log clearing events (Event ID 1102 = Security log cleared, 104 = System log cleared)
    let clear_script = r#"Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 10 -ErrorAction SilentlyContinue | ForEach-Object { Write-Output "$($_.TimeCreated)|$($_.Message)" }"#;
    if let Some(output) = run_ps(clear_script) {
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                send(tx, Finding::new(Severity::Danger, MODULE, "Log Cleared",
                    "Security Event Log was cleared")
                    .with_detail(trimmed));
            }
        }
    }

    // Check if any critical event logs are disabled
    let disabled_script = r#"Get-WinEvent -ListLog Security,System,Application -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled -eq $false } | ForEach-Object { Write-Output $_.LogName }"#;
    if let Some(output) = run_ps(disabled_script) {
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                send(tx, Finding::new(Severity::Danger, MODULE, "Log Disabled",
                    &format!("Critical event log is DISABLED: {}", trimmed)));
            }
        }
    }

    // Failed logins (Event ID 4625) — brute force detection
    let brute_script = r#"$count = (Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 1000 -ErrorAction SilentlyContinue | Measure-Object).Count; Write-Output $count"#;
    if let Some(output) = run_ps(brute_script) {
        if let Ok(count) = output.trim().parse::<u32>() {
            if count > 100 {
                send(tx, Finding::new(Severity::Warning, MODULE, "Brute Force",
                    &format!("{} failed login attempts detected", count)));
            } else if count > 0 {
                send(tx, Finding::new(Severity::Info, MODULE, "Failed Logins",
                    &format!("{} failed login attempt(s) in security log", count)));
            }
        }
    }

    // Windows Defender disabled
    let defender_script = r#"(Get-MpPreference -ErrorAction SilentlyContinue).DisableRealtimeMonitoring"#;
    if let Some(output) = run_ps(defender_script) {
        if output.trim().to_lowercase() == "true" {
            send(tx, Finding::new(Severity::Danger, MODULE, "Defender Off",
                "Windows Defender real-time monitoring is DISABLED"));
        }
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  PUBLIC ENTRY POINT
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub fn scan(tx: Sender) {
    let start = Instant::now();
    let _ = tx.send(ScanEvent::ModuleStart(MODULE.to_string()));

    persistence_scan(&tx);
    dll_injection_scan(&tx);
    process_scan(&tx);
    network_scan(&tx);
    credential_scan(&tx);
    driver_scan(&tx);
    eventlog_scan(&tx);

    let _ = tx.send(ScanEvent::ModuleDone(MODULE.to_string(), start.elapsed()));
}
