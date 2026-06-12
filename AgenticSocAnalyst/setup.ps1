# setup.ps1 — Windows PowerShell setup helper for Agentic AI SOC Analyst

Write-Host "=== Agentic AI SOC Analyst Setup ===" -ForegroundColor Cyan

# 1. Copy env template
if (-Not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[OK] .env created from .env.example. Please fill in your API keys." -ForegroundColor Yellow
} else {
    Write-Host "[SKIP] .env already exists." -ForegroundColor Green
}

# 2. Create Python virtual environment
if (-Not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "[OK] Virtual environment created." -ForegroundColor Green
}

# 3. Activate venv and install dependencies
& .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
Write-Host "[OK] Dependencies installed." -ForegroundColor Green

Write-Host "`nSetup complete! Run 'docker-compose up --build' to start." -ForegroundColor Cyan
