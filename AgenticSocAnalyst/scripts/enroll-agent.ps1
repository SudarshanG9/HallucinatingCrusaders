# =============================================================================
# Enroll a Wazuh Agent on this Windows machine
# Run AFTER setup.ps1 and after the Wazuh stack is healthy
# =============================================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Wazuh Agent Enrollment -- Windows" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$WAZUH_MANAGER = "127.0.0.1"
$AGENT_NAME    = $env:COMPUTERNAME
$AGENT_GROUP   = "default"

Write-Host "  Manager IP:  $WAZUH_MANAGER" -ForegroundColor White
Write-Host "  Agent Name:  $AGENT_NAME" -ForegroundColor White
Write-Host "  Group:       $AGENT_GROUP" -ForegroundColor White
Write-Host ""

# Check if agent already installed
$wazuhSvc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($wazuhSvc) {
    Write-Host "  [INFO] Wazuh agent already installed. Status: $($wazuhSvc.Status)" -ForegroundColor Yellow
    Write-Host "  To re-enroll, first uninstall via Add/Remove Programs." -ForegroundColor DarkGray
    exit 0
}

Write-Host "[1/3] Downloading Wazuh Windows agent installer..." -ForegroundColor Yellow

$installerUrl  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.3-1.msi"
$installerPath = "$env:TEMP\wazuh-agent.msi"

$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
    Write-Host "  [OK] Downloaded to $installerPath" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Download failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
$ProgressPreference = 'Continue'

Write-Host ""
Write-Host "[2/3] Installing Wazuh agent (this takes ~30 seconds)..." -ForegroundColor Yellow

$installArgs = @(
    "/i", $installerPath,
    "/qn",
    "WAZUH_MANAGER=$WAZUH_MANAGER",
    "WAZUH_AGENT_NAME=$AGENT_NAME",
    "WAZUH_AGENT_GROUP=$AGENT_GROUP",
    "/L*v", "$env:TEMP\wazuh-install.log"
)

$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -NoNewWindow -PassThru
if ($proc.ExitCode -eq 0) {
    Write-Host "  [OK] Agent installed successfully" -ForegroundColor Green
} else {
    Write-Host "  [ERROR] Installer exited with code $($proc.ExitCode)" -ForegroundColor Red
    Write-Host "  Check log: $env:TEMP\wazuh-install.log" -ForegroundColor DarkGray
    exit 1
}

Write-Host ""
Write-Host "[3/3] Starting Wazuh agent service..." -ForegroundColor Yellow

Start-Sleep -Seconds 3
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 5

$svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "  [OK] Wazuh agent is running!" -ForegroundColor Green
} else {
    $status = if ($svc) { $svc.Status } else { "Not found" }
    Write-Host "  [WARN] Agent service status: $status" -ForegroundColor Yellow
    Write-Host "  Check: C:\Program Files (x86)\ossec-agent\ossec.log" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Agent enrolled! Open the Wazuh Dashboard to verify." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard: https://localhost:443  -> Agents" -ForegroundColor Cyan
Write-Host "  Agent log: C:\Program Files (x86)\ossec-agent\ossec.log" -ForegroundColor DarkGray
Write-Host ""
