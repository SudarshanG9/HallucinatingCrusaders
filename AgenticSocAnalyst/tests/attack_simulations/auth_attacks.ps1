# =============================================================================
# Phase 2 — Authentication Attack Simulations
# Generates Windows Security events that Wazuh will detect as alerts.
#
# MUST RUN AS ADMINISTRATOR
#
# What this produces:
#   - Event 4625: Failed logon attempts (brute force pattern)
#   - Event 4720/4726: User creation/deletion (persistence)
#   - Event 4732/4733: User added/removed from admin group
#   - Wazuh rules: 18100-18199 (Windows authentication rules)
#   - Wazuh rules: 60100-60199 (Windows audit rules)
# =============================================================================

param(
    [int]$BruteForceCount = 10,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    Write-Host "[$ts] [$Type] $Message"
}

Write-Status "=== Authentication Attack Simulations ===" "START"
Write-Status "Generating Windows Security events for Wazuh detection..."

# -------------------------------------------------------------------------
# 1. Brute Force Login (Failed Logon — Event 4625)
# -------------------------------------------------------------------------
Write-Status "--- Simulation 1: Brute Force Login Attempts ---"
Write-Status "Attempting $BruteForceCount failed logins with bad credentials..."

$targetUser = "brute_target"
$badPasswords = @(
    "password123", "admin", "letmein", "12345678",
    "qwerty", "monkey", "dragon", "master",
    "abc123", "iloveyou", "trustno1", "sunshine"
)

for ($i = 1; $i -le $BruteForceCount; $i++) {
    $pw = $badPasswords[($i - 1) % $badPasswords.Count]
    $secPw = ConvertTo-SecureString $pw -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential(".\$targetUser", $secPw)

    try {
        # Start-Process with bad creds generates Event 4625
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c whoami" -Credential $cred -NoNewWindow -Wait -ErrorAction Stop 2>$null
    } catch {
        if ($Verbose) {
            Write-Status "  Failed login attempt $i/$BruteForceCount (user: $targetUser, pw: $pw)" "ATTACK"
        }
    }

    # Small delay to avoid overwhelming the log
    Start-Sleep -Milliseconds 500
}
Write-Status "Generated $BruteForceCount failed login events (Event 4625)" "OK"

# -------------------------------------------------------------------------
# 2. Password Spray (Multiple users, same password)
# -------------------------------------------------------------------------
Write-Status "--- Simulation 2: Password Spray Attack ---"

$sprayUsers = @("admin", "administrator", "guest", "user1", "service_account", "backup_admin")
$sprayPassword = "Summer2026!"

foreach ($user in $sprayUsers) {
    $secPw = ConvertTo-SecureString $sprayPassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential(".\$user", $secPw)

    try {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c echo test" -Credential $cred -NoNewWindow -Wait -ErrorAction Stop 2>$null
    } catch {
        if ($Verbose) {
            Write-Status "  Spray attempt: user=$user" "ATTACK"
        }
    }

    Start-Sleep -Milliseconds 300
}
Write-Status "Generated $(($sprayUsers).Count) password spray events" "OK"

# -------------------------------------------------------------------------
# 3. Suspicious Account Management (Create/Delete user — Event 4720/4726)
# -------------------------------------------------------------------------
Write-Status "--- Simulation 3: Suspicious Account Creation ---"

$suspiciousUser = "svc_backdoor"

# Create a suspicious user account
try {
    net user $suspiciousUser "P@ssw0rd123!" /add 2>$null | Out-Null
    Write-Status "  Created user: $suspiciousUser (Event 4720)" "ATTACK"
} catch {
    Write-Status "  Could not create user (may already exist)" "WARN"
}

Start-Sleep -Seconds 1

# Add to Administrators group (Event 4732 — member added to security-enabled local group)
try {
    net localgroup Administrators $suspiciousUser /add 2>$null | Out-Null
    Write-Status "  Added $suspiciousUser to Administrators group (Event 4732)" "ATTACK"
} catch {
    Write-Status "  Could not add to admins (may already be member)" "WARN"
}

Start-Sleep -Seconds 2

# Remove from Administrators (Event 4733)
try {
    net localgroup Administrators $suspiciousUser /delete 2>$null | Out-Null
    Write-Status "  Removed $suspiciousUser from Administrators group (Event 4733)" "ATTACK"
} catch {
    Write-Status "  Could not remove from admins" "WARN"
}

# Delete the user (Event 4726)
try {
    net user $suspiciousUser /delete 2>$null | Out-Null
    Write-Status "  Deleted user: $suspiciousUser (Event 4726)" "ATTACK"
} catch {
    Write-Status "  Could not delete user" "WARN"
}

Write-Status "Generated account management events (4720, 4726, 4732, 4733)" "OK"

# -------------------------------------------------------------------------
# 4. Logon with Explicit Credentials (Event 4648)
# -------------------------------------------------------------------------
Write-Status "--- Simulation 4: Explicit Credential Usage ---"

# runas generates Event 4648 (logon using explicit credentials)
$fakeUser = "fake_service"
$fakePw = ConvertTo-SecureString "FakeP@ss1" -AsPlainText -Force
$fakeCred = New-Object System.Management.Automation.PSCredential(".\$fakeUser", $fakePw)

for ($i = 1; $i -le 3; $i++) {
    try {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c hostname" -Credential $fakeCred -NoNewWindow -Wait -ErrorAction Stop 2>$null
    } catch {
        if ($Verbose) {
            Write-Status "  Explicit credential attempt $i (Event 4648)" "ATTACK"
        }
    }
    Start-Sleep -Milliseconds 500
}
Write-Status "Generated 3 explicit credential events (Event 4648)" "OK"

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
$totalEvents = $BruteForceCount + $sprayUsers.Count + 4 + 3
Write-Status "=== Authentication Simulations Complete ===" "DONE"
Write-Status "Total events generated: ~$totalEvents"
Write-Status "Expected Wazuh rules: 18100-18199 (auth), 60100-60199 (audit)"
Write-Status "Check Wazuh Dashboard -> Security Events in ~60 seconds"
