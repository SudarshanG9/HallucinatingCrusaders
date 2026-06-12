# =============================================================================
# Phase 2 — System Abuse / Reconnaissance Simulations
# Generates system audit events that Wazuh will detect as suspicious activity.
#
# MUST RUN AS ADMINISTRATOR
#
# What this produces:
#   - Reconnaissance commands (whoami, net user, net localgroup)
#   - Scheduled task creation (persistence — Event 4698)
#   - Registry Run key modification (persistence — Event 4657)
#   - Service creation (Event 7045)
#   - Firewall rule modification
#   - Process enumeration (MITRE T1057)
#   - Wazuh rules: 61100+ (Windows audit), 92000+ (command monitoring)
# =============================================================================

param(
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] [$Type] $Message"
}

Write-Status "=== System Abuse / Recon Simulations ===" "START"

# -------------------------------------------------------------------------
# 1. Reconnaissance Commands (MITRE T1033, T1087, T1082)
#    Attackers run these to understand the compromised system.
#    Wazuh detects via command monitoring rules.
# -------------------------------------------------------------------------
Write-Status "--- Simulation 1: Reconnaissance Commands ---"

$reconCommands = @(
    @{ Cmd = "whoami"; Desc = "Current user identity (T1033)" },
    @{ Cmd = "whoami /priv"; Desc = "User privileges enumeration (T1033)" },
    @{ Cmd = "whoami /groups"; Desc = "Group membership enumeration (T1033)" },
    @{ Cmd = "net user"; Desc = "Local user enumeration (T1087.001)" },
    @{ Cmd = "net localgroup"; Desc = "Local group enumeration (T1087.001)" },
    @{ Cmd = "net localgroup Administrators"; Desc = "Admin group members (T1087.001)" },
    @{ Cmd = "systeminfo"; Desc = "System information gathering (T1082)" },
    @{ Cmd = "ipconfig /all"; Desc = "Network configuration (T1016)" },
    @{ Cmd = "netstat -an"; Desc = "Network connections (T1049)" },
    @{ Cmd = "arp -a"; Desc = "ARP cache (T1016)" },
    @{ Cmd = "route print"; Desc = "Routing table (T1016)" },
    @{ Cmd = "tasklist"; Desc = "Process enumeration (T1057)" },
    @{ Cmd = "net share"; Desc = "Network share enumeration (T1135)" },
    @{ Cmd = "net session"; Desc = "Active sessions (T1049)" },
    @{ Cmd = "wmic process list brief"; Desc = "WMI process list (T1057)" }
)

foreach ($recon in $reconCommands) {
    try {
        cmd.exe /c $recon.Cmd 2>$null | Out-Null
        if ($Verbose) {
            Write-Status "  Executed: $($recon.Cmd) - $($recon.Desc)" "ATTACK"
        }
    } catch {
        Write-Status "  Failed: $($recon.Cmd)" "WARN"
    }
    Start-Sleep -Milliseconds 300
}
Write-Status "Generated $($reconCommands.Count) reconnaissance events" "OK"

# -------------------------------------------------------------------------
# 2. Scheduled Task Creation (MITRE T1053.005 — Persistence)
#    Attackers create scheduled tasks to maintain persistence.
#    Generates Event 4698 (scheduled task created)
# -------------------------------------------------------------------------
Write-Status "--- Simulation 2: Scheduled Task Persistence ---"

$taskName = "SOCTestPersistence"
$taskAction = "cmd.exe /c echo SOC Test Task Executed"

try {
    # Create a scheduled task (triggers Event 4698)
    schtasks.exe /Create /TN $taskName /TR $taskAction /SC ONCE /ST 23:59 /F 2>$null | Out-Null
    Write-Status "  Created scheduled task: $taskName (Event 4698)" "ATTACK"

    Start-Sleep -Seconds 2

    # Delete it immediately (triggers Event 4699)
    schtasks.exe /Delete /TN $taskName /F 2>$null | Out-Null
    Write-Status "  Deleted scheduled task: $taskName (Event 4699)" "CLEAN"
} catch {
    Write-Status "  Scheduled task operations failed" "WARN"
}

# Create another with a suspicious name
$taskName2 = "WindowsUpdateHelper"
try {
    schtasks.exe /Create /TN $taskName2 /TR "powershell.exe -WindowStyle Hidden -Command Get-Date" /SC ONLOGON /F 2>$null | Out-Null
    Write-Status "  Created suspicious task: $taskName2 (runs on logon)" "ATTACK"
    Start-Sleep -Seconds 2
    schtasks.exe /Delete /TN $taskName2 /F 2>$null | Out-Null
    Write-Status "  Deleted: $taskName2" "CLEAN"
} catch {
    Write-Status "  Second scheduled task failed" "WARN"
}

# -------------------------------------------------------------------------
# 3. Registry Run Key Modification (MITRE T1547.001 — Boot Persistence)
#    Attackers add registry run keys to execute on startup.
#    Wazuh monitors registry changes via syscheck.
# -------------------------------------------------------------------------
Write-Status "--- Simulation 3: Registry Run Key Persistence ---"

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$regName = "SOCTestPersistence"
$regValue = "C:\Windows\Temp\soc_test_payload.exe"

try {
    # Add a run key (persistence technique)
    Set-ItemProperty -Path $regPath -Name $regName -Value $regValue -ErrorAction Stop
    Write-Status "  Added Run key: $regName -> $regValue" "ATTACK"

    Start-Sleep -Seconds 2

    # Remove it
    Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop
    Write-Status "  Removed Run key: $regName" "CLEAN"
} catch {
    Write-Status "  Registry operation failed: $_" "WARN"
}

# Also try HKLM (requires admin)
$regPathLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
$regNameLM = "SOCTestService"
$regValueLM = "C:\Windows\Temp\soc_backdoor.exe"

try {
    Set-ItemProperty -Path $regPathLM -Name $regNameLM -Value $regValueLM -ErrorAction Stop
    Write-Status "  Added HKLM Run key: $regNameLM (system-wide persistence)" "ATTACK"

    Start-Sleep -Seconds 2

    Remove-ItemProperty -Path $regPathLM -Name $regNameLM -ErrorAction Stop
    Write-Status "  Removed HKLM Run key: $regNameLM" "CLEAN"
} catch {
    Write-Status "  HKLM registry operation failed (may need higher privileges)" "WARN"
}

# -------------------------------------------------------------------------
# 4. Service Creation Attempt (MITRE T1543.003 — Service Persistence)
#    Attackers create Windows services for persistence.
#    Generates Event 7045 (new service installed)
# -------------------------------------------------------------------------
Write-Status "--- Simulation 4: Service Creation ---"

$svcName = "SOCTestSvc"
$svcBin = "C:\Windows\Temp\soc_test_svc.exe"

try {
    sc.exe create $svcName binPath= $svcBin start= auto 2>$null | Out-Null
    Write-Status "  Created service: $svcName (Event 7045)" "ATTACK"

    Start-Sleep -Seconds 2

    sc.exe delete $svcName 2>$null | Out-Null
    Write-Status "  Deleted service: $svcName" "CLEAN"
} catch {
    Write-Status "  Service operations failed" "WARN"
}

# -------------------------------------------------------------------------
# 5. Firewall Rule Manipulation (MITRE T1562.004 — Impair Defenses)
#    Attackers modify firewall rules to allow C2 traffic.
# -------------------------------------------------------------------------
Write-Status "--- Simulation 5: Firewall Rule Manipulation ---"

$fwRuleName = "SOC Test Rule - Allow Inbound"

try {
    netsh advfirewall firewall add rule name="$fwRuleName" dir=in action=allow protocol=tcp localport=4444 2>$null | Out-Null
    Write-Status "  Added firewall rule: allow TCP 4444 inbound" "ATTACK"

    Start-Sleep -Seconds 2

    netsh advfirewall firewall delete rule name="$fwRuleName" 2>$null | Out-Null
    Write-Status "  Removed firewall rule" "CLEAN"
} catch {
    Write-Status "  Firewall manipulation failed" "WARN"
}

# -------------------------------------------------------------------------
# 6. WMI Event Subscription Attempt (MITRE T1546.003)
#    Attackers use WMI subscriptions for fileless persistence.
# -------------------------------------------------------------------------
Write-Status "--- Simulation 6: WMI Persistence Attempt ---"

try {
    # Create a WMI event filter (triggers WMI audit events)
    $filterName = "SOCTestFilter"
    $query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"

    $filter = Set-WmiInstance -Namespace "root\subscription" -Class "__EventFilter" -Arguments @{
        Name = $filterName
        EventNameSpace = "root\cimv2"
        QueryLanguage = "WQL"
        Query = $query
    } -ErrorAction Stop

    Write-Status "  Created WMI event filter: $filterName" "ATTACK"

    Start-Sleep -Seconds 2

    # Clean up
    $filter | Remove-WmiObject -ErrorAction SilentlyContinue
    Write-Status "  Removed WMI event filter" "CLEAN"
} catch {
    Write-Status "  WMI persistence simulation failed: $_" "WARN"
}

# -------------------------------------------------------------------------
# 7. Hosts File Modification (MITRE T1565.001 — Data Manipulation)
#    Attackers modify hosts file to redirect DNS.
# -------------------------------------------------------------------------
Write-Status "--- Simulation 7: Hosts File Modification ---"

$hostsFile = "C:\Windows\System32\drivers\etc\hosts"
$marker = "# SOC-TEST-ENTRY"
$fakeEntry = "127.0.0.1 malicious-c2-server.evil.com $marker"

try {
    $originalContent = Get-Content $hostsFile -Raw -ErrorAction Stop

    # Append a fake malicious entry
    Add-Content -Path $hostsFile -Value "`r`n$fakeEntry" -ErrorAction Stop
    Write-Status "  Modified hosts file (DNS redirect simulation)" "ATTACK"

    Start-Sleep -Seconds 2

    # Clean up — remove only our test entry
    $cleaned = (Get-Content $hostsFile) | Where-Object { $_ -notmatch "SOC-TEST-ENTRY" }
    $cleaned | Set-Content $hostsFile -ErrorAction Stop
    Write-Status "  Restored hosts file" "CLEAN"
} catch {
    Write-Status "  Hosts file modification failed: $_" "WARN"
}

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
$totalEvents = $reconCommands.Count + 4 + 2 + 2 + 2 + 2 + 2
Write-Status "=== System Abuse Simulations Complete ===" "DONE"
Write-Status "Total events generated: ~$totalEvents"
Write-Status "MITRE coverage: T1033, T1087, T1082, T1016, T1049, T1057, T1135, T1053, T1547, T1543, T1562, T1546, T1565"
Write-Status "Check Wazuh Dashboard -> Security Events in ~60 seconds"
