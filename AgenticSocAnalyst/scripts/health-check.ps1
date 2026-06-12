#!/usr/bin/env pwsh
# =============================================================================
# Health Check Script — Verify Phase 1 is complete
# Run after: setup.ps1 + enroll-agent.ps1
# =============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  Phase 1 Health Check" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$allGood = $true

# ─────────────────────────────────────────────────────────────────────────────
# Check 1: Docker containers
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "🐳 Docker Containers:" -ForegroundColor Yellow

$containers = @("wazuh.manager", "wazuh.indexer", "wazuh.dashboard", "soc-postgres", "soc-chromadb")
foreach ($container in $containers) {
    $status = docker inspect --format='{{.State.Status}}' $container 2>$null
    if ($status -eq "running") {
        Write-Host "  ✅ $container — running" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $container — $status" -ForegroundColor Red
        $allGood = $false
    }
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Check 2: Wazuh API
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "🔌 Wazuh API (https://localhost:55000):" -ForegroundColor Yellow

try {
    # Get JWT token
    $authResponse = Invoke-RestMethod `
        -Uri "https://localhost:55000/security/user/authenticate?raw=true" `
        -Method POST `
        -Credential (New-Object PSCredential("wazuh-wui", (ConvertTo-SecureString "MyS3cr37P450r.*-" -AsPlainText -Force))) `
        -SkipCertificateCheck `
        -ErrorAction Stop
    
    Write-Host "  ✅ API authentication successful" -ForegroundColor Green
    $token = $authResponse
    
    # Check manager status
    $statusResponse = Invoke-RestMethod `
        -Uri "https://localhost:55000/manager/status" `
        -Headers @{Authorization = "Bearer $token"} `
        -SkipCertificateCheck
    
    Write-Host "  ✅ Manager status: OK" -ForegroundColor Green
    
    # Check agents
    $agentsResponse = Invoke-RestMethod `
        -Uri "https://localhost:55000/agents?status=active" `
        -Headers @{Authorization = "Bearer $token"} `
        -SkipCertificateCheck
    
    $agentCount = $agentsResponse.data.total_affected_items
    if ($agentCount -gt 0) {
        Write-Host "  ✅ Active agents: $agentCount" -ForegroundColor Green
        $agentsResponse.data.affected_items | ForEach-Object {
            Write-Host "     → $($_.name) [$($_.id)] — $($_.ip)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  ⚠️  No active agents connected yet" -ForegroundColor Yellow
        Write-Host "     Run: .\scripts\enroll-agent.ps1" -ForegroundColor DarkGray
    }
    
} catch {
    Write-Host "  ❌ API not reachable: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "     Wait 2-3 more minutes for services to fully start" -ForegroundColor DarkGray
    $allGood = $false
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Check 3: PostgreSQL
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "🗄️  PostgreSQL:" -ForegroundColor Yellow

try {
    $pgCheck = docker exec soc-postgres pg_isready -U soc_user -d soc_analyst 2>&1
    if ($pgCheck -match "accepting connections") {
        Write-Host "  ✅ PostgreSQL accepting connections" -ForegroundColor Green
        
        # Check tables exist
        $tables = docker exec soc-postgres psql -U soc_user -d soc_analyst -c "\dt" 2>&1
        if ($tables -match "alerts") {
            Write-Host "  ✅ Database schema initialized (alerts table exists)" -ForegroundColor Green
        } else {
            Write-Host "  ⚠️  Schema not initialized yet" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ❌ PostgreSQL not ready" -ForegroundColor Red
        $allGood = $false
    }
} catch {
    Write-Host "  ❌ $($_.Exception.Message)" -ForegroundColor Red
    $allGood = $false
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Check 4: Wazuh Indexer
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "📊 Wazuh Indexer (https://localhost:9200):" -ForegroundColor Yellow

try {
    $indexerHealth = Invoke-RestMethod `
        -Uri "https://localhost:9200/_cluster/health" `
        -Credential (New-Object PSCredential("admin", (ConvertTo-SecureString "SecretPassword" -AsPlainText -Force))) `
        -SkipCertificateCheck `
        -ErrorAction Stop
    
    $healthColor = if ($indexerHealth.status -eq "green") { "Green" } elseif ($indexerHealth.status -eq "yellow") { "Yellow" } else { "Red" }
    Write-Host "  ✅ Cluster health: $($indexerHealth.status)" -ForegroundColor $healthColor
} catch {
    Write-Host "  ⚠️  Indexer not ready yet (may still be initializing)" -ForegroundColor Yellow
}

Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
Write-Host "============================================================" -ForegroundColor Cyan
if ($allGood) {
    Write-Host "  ✅ Phase 1 Complete! All systems operational." -ForegroundColor Green
    Write-Host ""
    Write-Host "  Next Steps:" -ForegroundColor Cyan
    Write-Host "  1. Open the Wazuh Dashboard: https://localhost:443" -ForegroundColor White
    Write-Host "  2. Login with: admin / SecretPassword" -ForegroundColor White
    Write-Host "  3. Navigate to: Agents → check your agent is 'Active'" -ForegroundColor White
    Write-Host "  4. Move to Phase 2: Generate security events" -ForegroundColor White
    Write-Host "     Run: .\tests\attack_simulations\simulate-phase2.ps1" -ForegroundColor White
} else {
    Write-Host "  ⚠️  Some checks failed. Review errors above." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Common fixes:" -ForegroundColor Cyan
    Write-Host "  • Wait 3-5 more minutes for Wazuh to fully initialize" -ForegroundColor White
    Write-Host "  • Check logs: docker-compose logs wazuh.manager" -ForegroundColor White  
    Write-Host "  • Check memory: Wazuh needs at least 4GB for Docker" -ForegroundColor White
    Write-Host "  • Restart WSL2: wsl --shutdown (then restart Docker Desktop)" -ForegroundColor White
}
Write-Host "============================================================" -ForegroundColor Cyan
