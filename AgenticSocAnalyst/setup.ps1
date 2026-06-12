# =============================================================================
# HallucinatingCrusaders - Windows Setup Script (Phase 1)
# Run this script in PowerShell as Administrator
# It will: check prerequisites, generate certs, and start the Wazuh stack
# =============================================================================

$ErrorActionPreference = "Stop"
$StackRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  HallucinatingCrusaders - Phase 1 Setup" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# STEP 1: Check Prerequisites
# -----------------------------------------------------------------------------
Write-Host "[1/6] Checking prerequisites..." -ForegroundColor Yellow

# Check Docker
try {
    $dockerVersion = docker --version 2>&1
    Write-Host "  [OK] Docker: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Docker Desktop not found. Install from: https://www.docker.com/products/docker-desktop" -ForegroundColor Red
    exit 1
}

# Check Docker daemon is running
try {
    docker info 2>&1 | Out-Null
    Write-Host "  [OK] Docker daemon is running" -ForegroundColor Green
} catch {
    Write-Host "  [ERROR] Docker daemon is not running. Please start Docker Desktop." -ForegroundColor Red
    exit 1
}

# Check WSL2
try {
    $wslStatus = wsl --status 2>&1
    Write-Host "  [OK] WSL detected" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] WSL not detected. Wazuh requires WSL2 backend in Docker Desktop." -ForegroundColor Yellow
}

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "  [OK] Python: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Python not found. Install from: https://www.python.org/downloads/" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
# STEP 2: Create directory structure
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/6] Creating project directory structure..." -ForegroundColor Yellow

$dirs = @(
    "infrastructure\certs",
    "infrastructure\wazuh-manager",
    "infrastructure\wazuh-indexer",
    "infrastructure\wazuh-dashboard",
    "infrastructure\postgres",
    "collector",
    "agents\analyst",
    "agents\tools",
    "agents\workflows",
    "agents\crew",
    "memory",
    "responder",
    "api\routers",
    "api\schemas",
    "dashboard",
    "tests\attack_simulations"
)

foreach ($dir in $dirs) {
    $fullPath = Join-Path $StackRoot $dir
    if (-not (Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
        Write-Host "  [DIR] Created: $dir" -ForegroundColor DarkGray
    }
}
Write-Host "  [OK] Directory structure ready" -ForegroundColor Green

# -----------------------------------------------------------------------------
# STEP 3: Generate TLS Certificates
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/6] Generating TLS certificates..." -ForegroundColor Yellow

$certsDir = Join-Path $StackRoot "infrastructure\certs"
$certsConfigPath = Join-Path $StackRoot "infrastructure\certs-config.yml"

# Write cert config file
$certsConfigContent = @"
nodes:
  indexer:
    - name: wazuh.indexer
      ip: "wazuh.indexer"

  server:
    - name: wazuh.manager
      ip: "wazuh.manager"

  dashboard:
    - name: wazuh.dashboard
      ip: "wazuh.dashboard"
"@

$certsConfigContent | Out-File -FilePath $certsConfigPath -Encoding UTF8

Write-Host "  Running Wazuh cert generator (this may take 30-60 seconds)..." -ForegroundColor DarkGray

docker run --rm `
    -v "${certsConfigPath}:/config/certs.yml" `
    -v "${certsDir}:/certificates" `
    wazuh/wazuh-certs-generator:0.0.1

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Certificates generated successfully" -ForegroundColor Green

    # Flatten nested cert structure
    $certSubdirs = @("wazuh.indexer", "wazuh.manager", "wazuh.dashboard", "admin")
    foreach ($subdir in $certSubdirs) {
        $subdirPath = Join-Path $certsDir $subdir
        if (Test-Path $subdirPath) {
            Get-ChildItem $subdirPath -Filter "*.pem" | ForEach-Object {
                Copy-Item $_.FullName $certsDir -Force
                Write-Host "  [CERT] Copied: $($_.Name)" -ForegroundColor DarkGray
            }
        }
    }

    # Create root-ca alias for manager (used by filebeat inside the container)
    $rootCaSource = Join-Path $certsDir "root-ca.pem"
    $rootCaAlias  = Join-Path $certsDir "root-ca-manager.pem"
    if ((Test-Path $rootCaSource) -and (-not (Test-Path $rootCaAlias))) {
        Copy-Item $rootCaSource $rootCaAlias
        Write-Host "  [CERT] Created root-ca-manager.pem alias" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [ERROR] Certificate generation failed. Is Docker running?" -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------------
# STEP 4: Configure WSL2 memory (Wazuh needs >= 4GB)
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "[4/6] Checking Docker resource limits..." -ForegroundColor Yellow

$wslConfigPath = "$env:USERPROFILE\.wslconfig"
if (-not (Test-Path $wslConfigPath)) {
    $wslConfig = @"
[wsl2]
memory=6GB
processors=4
swap=2GB
"@
    $wslConfig | Out-File -FilePath $wslConfigPath -Encoding UTF8
    Write-Host "  [OK] Created .wslconfig (6GB RAM for WSL2)" -ForegroundColor Green
    Write-Host "  [WARN] Restart WSL2 for this to take effect: wsl --shutdown" -ForegroundColor Yellow
} else {
    Write-Host "  [INFO] .wslconfig already exists at $wslConfigPath" -ForegroundColor DarkGray
    Write-Host "         Make sure at least 4GB is allocated." -ForegroundColor DarkGray
}

# -----------------------------------------------------------------------------
# STEP 5: Pull Docker images
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "[5/6] Pulling Docker images (this may take several minutes on first run)..." -ForegroundColor Yellow

$images = @(
    "wazuh/wazuh-manager:4.7.3",
    "wazuh/wazuh-indexer:4.7.3",
    "wazuh/wazuh-dashboard:4.7.3",
    "postgres:16-alpine",
    "chromadb/chroma:latest"
)

foreach ($image in $images) {
    Write-Host "  Pulling $image ..." -ForegroundColor DarkGray
    docker pull $image
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [OK] $image" -ForegroundColor Green
    } else {
        Write-Host "  [ERROR] Failed to pull $image" -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# STEP 6: Start the stack
# -----------------------------------------------------------------------------
Write-Host ""
Write-Host "[6/6] Starting Wazuh stack..." -ForegroundColor Yellow
Write-Host "  This will take 2-3 minutes for all services to become healthy." -ForegroundColor DarkGray

Set-Location $StackRoot
docker-compose up -d

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host "  Wazuh Stack is starting up!" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Wazuh Dashboard : https://localhost:443" -ForegroundColor Cyan
    Write-Host "    Username      : admin" -ForegroundColor White
    Write-Host "    Password      : SecretPassword" -ForegroundColor White
    Write-Host ""
    Write-Host "  Wazuh API       : https://localhost:55000" -ForegroundColor Cyan
    Write-Host "    Username      : wazuh-wui" -ForegroundColor White
    Write-Host "    Password      : MyS3cr37P450r.*-" -ForegroundColor White
    Write-Host ""
    Write-Host "  PostgreSQL      : localhost:5432" -ForegroundColor Cyan
    Write-Host "    DB/User/Pass  : soc_analyst / soc_user / soc_password" -ForegroundColor White
    Write-Host ""
    Write-Host "  ChromaDB        : http://localhost:8001" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Wait 2-3 minutes, then open: https://localhost:443" -ForegroundColor Yellow
    Write-Host "  (Accept the self-signed certificate warning in your browser)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Next step: .\scripts\enroll-agent.ps1" -ForegroundColor Yellow
    Write-Host ""

    # Show container status
    Write-Host "  Current container status:" -ForegroundColor DarkGray
    Start-Sleep -Seconds 5
    docker-compose ps
} else {
    Write-Host "  [ERROR] Failed to start stack. Check logs:" -ForegroundColor Red
    Write-Host "          docker-compose logs" -ForegroundColor White
    exit 1
}
