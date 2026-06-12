# =============================================================================
# Phase 2 — Master Attack Simulation Launcher
# Runs all attack simulation scripts in sequence and provides a summary.
#
# MUST RUN AS ADMINISTRATOR
#
# Usage:
#   .\simulate-phase2.ps1              # Run all simulations
#   .\simulate-phase2.ps1 -Verbose     # Run with detailed output
#   .\simulate-phase2.ps1 -SkipAuth    # Skip auth attacks
#   .\simulate-phase2.ps1 -SkipMalware # Skip malware sims
#   .\simulate-phase2.ps1 -SkipSystem  # Skip system abuse
# =============================================================================

param(
    [switch]$Verbose,
    [switch]$SkipAuth,
    [switch]$SkipMalware,
    [switch]$SkipSystem
)

$ErrorActionPreference = "Continue"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

function Write-Banner {
    param([string]$Message)
    $line = "=" * 70
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
    Write-Host ""
}

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $color = switch ($Type) {
        "OK"    { "Green" }
        "WARN"  { "Yellow" }
        "ERROR" { "Red" }
        "START" { "Cyan" }
        "DONE"  { "Green" }
        default { "White" }
    }
    Write-Host "[$ts] [$Type] $Message" -ForegroundColor $color
}

# =========================================================================
# Pre-flight Checks
# =========================================================================
Write-Banner "HallucinatingCrusaders -- Phase 2 Attack Simulations"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Status "This script MUST run as Administrator!" "ERROR"
    Write-Status "Right-click PowerShell -> Run as Administrator" "ERROR"
    exit 1
}
Write-Status "Running as Administrator" "OK"

# Check if Wazuh agent is running
$wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($wazuhSvc -and $wazuhSvc.Status -eq "Running") {
    Write-Status "Wazuh Agent (WazuhSvc) is running" "OK"
} else {
    Write-Status "Wazuh Agent is NOT running! Start it first: NET START WazuhSvc" "ERROR"
    exit 1
}

# Enable PowerShell script block logging (if not already enabled)
# This helps Wazuh detect encoded commands
try {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -ErrorAction SilentlyContinue
    Write-Status "PowerShell script block logging enabled" "OK"
} catch {
    Write-Status "Could not enable script block logging (non-critical)" "WARN"
}

Write-Host ""
$startTime = Get-Date

# =========================================================================
# Run Simulations
# =========================================================================

$results = @()

# --- 1. Authentication Attacks ---
if (-not $SkipAuth) {
    Write-Banner "Phase 2.1: Authentication Attacks"
    $authStart = Get-Date
    try {
        $authArgs = @{}
        if ($Verbose) { $authArgs["Verbose"] = $true }
        & "$scriptDir\auth_attacks.ps1" @authArgs
        $results += @{ Name = "Authentication Attacks"; Status = "PASS"; Duration = ((Get-Date) - $authStart).TotalSeconds }
    } catch {
        Write-Status "auth_attacks.ps1 failed: $_" "ERROR"
        $results += @{ Name = "Authentication Attacks"; Status = "FAIL"; Duration = ((Get-Date) - $authStart).TotalSeconds }
    }
    Write-Host ""
    Start-Sleep -Seconds 3
} else {
    Write-Status "Skipping authentication attacks (--SkipAuth)" "WARN"
}

# --- 2. Malware Simulation ---
if (-not $SkipMalware) {
    Write-Banner "Phase 2.2: Malware Simulation"
    $malStart = Get-Date
    try {
        $malArgs = @{}
        if ($Verbose) { $malArgs["Verbose"] = $true }
        & "$scriptDir\malware_sim.ps1" @malArgs
        $results += @{ Name = "Malware Simulation"; Status = "PASS"; Duration = ((Get-Date) - $malStart).TotalSeconds }
    } catch {
        Write-Status "malware_sim.ps1 failed: $_" "ERROR"
        $results += @{ Name = "Malware Simulation"; Status = "FAIL"; Duration = ((Get-Date) - $malStart).TotalSeconds }
    }
    Write-Host ""
    Start-Sleep -Seconds 3
} else {
    Write-Status "Skipping malware simulation (--SkipMalware)" "WARN"
}

# --- 3. System Abuse ---
if (-not $SkipSystem) {
    Write-Banner "Phase 2.3: System Abuse / Reconnaissance"
    $sysStart = Get-Date
    try {
        $sysArgs = @{}
        if ($Verbose) { $sysArgs["Verbose"] = $true }
        & "$scriptDir\system_abuse.ps1" @sysArgs
        $results += @{ Name = "System Abuse / Recon"; Status = "PASS"; Duration = ((Get-Date) - $sysStart).TotalSeconds }
    } catch {
        Write-Status "system_abuse.ps1 failed: $_" "ERROR"
        $results += @{ Name = "System Abuse / Recon"; Status = "FAIL"; Duration = ((Get-Date) - $sysStart).TotalSeconds }
    }
    Write-Host ""
} else {
    Write-Status "Skipping system abuse (--SkipSystem)" "WARN"
}

# =========================================================================
# Summary Report
# =========================================================================
$totalDuration = ((Get-Date) - $startTime).TotalSeconds

Write-Banner 'Phase 2 -- Simulation Summary'

Write-Host '  Simulation Results:' -ForegroundColor White
Write-Host '  -------------------' -ForegroundColor White

foreach ($r in $results) {
    $statusColor = if ($r.Status -eq 'PASS') { 'Green' } else { 'Red' }
    $duration = [math]::Round($r.Duration, 1)
    Write-Host ('    ' + $r.Name + ': ') -NoNewline -ForegroundColor White
    Write-Host $r.Status -NoNewline -ForegroundColor $statusColor
    Write-Host (' ' + $duration + ' sec') -ForegroundColor Gray
}

Write-Host ''
$roundedTotal = [math]::Round($totalDuration, 1)
Write-Host ('  Total Duration: ' + $roundedTotal + ' seconds') -ForegroundColor Cyan
Write-Host ''
Write-Host '  Expected Wazuh Alert Categories:' -ForegroundColor Yellow
Write-Host '    - authentication_failed    -- brute force, password spray' -ForegroundColor White
Write-Host '    - account_changed          -- user creation, group modification' -ForegroundColor White
Write-Host '    - file_integrity_monitoring -- EICAR, suspicious files' -ForegroundColor White
Write-Host '    - system_audit             -- recon commands, service creation' -ForegroundColor White
Write-Host '    - policy_changed           -- registry, firewall, scheduled task' -ForegroundColor White
Write-Host ''
Write-Host '  MITRE ATT and CK Coverage:' -ForegroundColor Yellow
Write-Host '    Recon:       T1033, T1087, T1082, T1016, T1049, T1057, T1135' -ForegroundColor White
Write-Host '    Persistence: T1053, T1547, T1543, T1546' -ForegroundColor White
Write-Host '    Defense Eva: T1562, T1027 -- encoded commands' -ForegroundColor White
Write-Host '    Impact:      T1565 -- hosts file modification' -ForegroundColor White
Write-Host ''
Write-Host '  Next Steps:' -ForegroundColor Cyan
Write-Host '    1. Wait 60 seconds for Wazuh to process events' -ForegroundColor White
Write-Host '    2. Open Wazuh Dashboard: https://localhost:443' -ForegroundColor White
Write-Host '    3. Navigate to: Security Events -> Events' -ForegroundColor White
Write-Host '    4. Filter by agent: MAXW' -ForegroundColor White
Write-Host '    5. Verify 50+ alerts across all categories' -ForegroundColor White
Write-Host ''
Write-Host '  Credentials: admin / SecretPassword' -ForegroundColor Gray
Write-Host ''
