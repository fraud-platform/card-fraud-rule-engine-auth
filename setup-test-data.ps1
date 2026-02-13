#!/usr/bin/env pwsh
# Card Fraud Rule Engine - Test Data Setup Script (PowerShell)
# Session 5.1: Automated test data setup for local development

param(
    [switch]$SkipBuild,
    [switch]$SkipTests,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$PROJECT = "card-fraud-rule-engine"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

# Colors for output (PowerShell 7+ supports ANSI colors)
$RED = "`e[0;31m"
$GREEN = "`e[0;32m"
$YELLOW = "`e[1;33m"
$BLUE = "`e[0;34m"
$NC = "`e[0m"

# Logging functions
function Log-Info($message) {
    Write-Host "${BLUE}[INFO]${NC} $message"
}

function Log-Success($message) {
    Write-Host "${GREEN}[SUCCESS]${NC} $message"
}

function Log-Warning($message) {
    Write-Host "${YELLOW}[WARNING]${NC} $message"
}

function Log-Error($message) {
    Write-Host "${RED}[ERROR]${NC} $message"
}

# Function to check if command exists
function Test-Command($command) {
    return [bool](Get-Command -Name $command -ErrorAction SilentlyContinue)
}

# Function to check if Docker container is running
function Test-ContainerRunning($containerName) {
    $containers = docker ps --format '{{.Names}}' 2>$null
    return $containers | Select-String -Pattern $containerName -Quiet
}

# Function to start infrastructure
function Start-Infrastructure {
    Log-Info "Starting local infrastructure..."
    
    # Check Docker
    if (-not (Test-Command docker)) {
        Log-Error "Docker not found. Please install Docker."
        exit 1
    }
    
    try {
        $null = docker info 2>$null
    } catch {
        Log-Error "Docker is not running. Please start Docker."
        exit 1
    }
    
    # Start all services
    docker-compose up -d
    
    # Wait for services to be healthy
    Log-Info "Waiting for services to start..."
    Start-Sleep -Seconds 5
    
    # Check Redis
    if (Test-ContainerRunning "card-fraud-rule-engine-redis") {
        $pingResult = docker exec card-fraud-rule-engine-redis redis-cli ping 2>$null
        if ($pingResult -eq "PONG") {
            Log-Success "Redis is healthy"
        } else {
            Log-Error "Redis is not responding"
            exit 1
        }
    } else {
        Log-Error "Redis container is not running"
        exit 1
    }
    
    # Check Redpanda
    if (Test-ContainerRunning "card-fraud-rule-engine-redpanda") {
        Log-Success "Redpanda is running"
    } else {
        Log-Warning "Redpanda container is not running (optional)"
    }
    
    Log-Success "Infrastructure started successfully"
}

# Function to upload sample rulesets
function Upload-Rulesets {
    Log-Info "Uploading sample rulesets to MinIO..."
    
    # Check if MinIO is accessible
    try {
        $response = Invoke-WebRequest -Uri "$env:S3_ENDPOINT_URL/minio/health/live" -Method GET -UseBasicParsing -ErrorAction SilentlyContinue
    } catch {
        Log-Warning "MinIO is not accessible. Rulesets must be uploaded from rule-management project."
        Log-Info "To upload rulesets, run from card-fraud-rule-management:"
        Log-Info "  uv run objstore-local-up"
        Log-Info "  cd ..\card-fraud-rule-engine"
        Log-Info "  python scripts\upload_sample_ruleset.py"
        return
    }
    
    # Run the Python upload script
    if (Test-Command python) {
        & python "$SCRIPT_DIR\upload_sample_ruleset.py"
    } elseif (Test-Command python3) {
        & python3 "$SCRIPT_DIR\upload_sample_ruleset.py"
    } else {
        Log-Warning "Python not found. Skipping ruleset upload."
    }
}

# Function to seed Redis with test data
function Seed-Redis {
    Log-Info "Seeding Redis with test data..."
    
    # Create some velocity test data
    $testCards = @("test-card-001", "test-card-002", "test-card-003")
    
    foreach ($card in $testCards) {
        # Initialize velocity counters for testing
        docker exec card-fraud-rule-engine-redis redis-cli `
            EVAL "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], 3600) end; return count" `
            1 "vel:global:card_hash:$card" 2>$null
    }
    
    Log-Success "Redis test data seeded"
}

# Function to build the application
function Build-Application {
    Log-Info "Building application..."
    
    if (-not (Test-Command mvn)) {
        Log-Warning "Maven not found. Skipping build."
        return
    }
    
    Push-Location (Join-Path $SCRIPT_DIR "..")
    try {
        mvn clean package -DskipTests -q
        Log-Success "Application built successfully"
    } finally {
        Pop-Location
    }
}

# Function to run tests
function Run-Tests {
    Log-Info "Running tests to verify setup..."
    
    Push-Location (Join-Path $SCRIPT_DIR "..")
    try {
        # Run smoke tests first
        $smokeResult = mvn test -Psmoke -q 2>$null
        if ($LASTEXITCODE -eq 0) {
            Log-Success "Smoke tests passed"
        } else {
            Log-Warning "Some smoke tests failed (this is OK if app is not running)"
        }
        
        # Run unit tests
        $unitResult = mvn test -q 2>$null
        if ($LASTEXITCODE -eq 0) {
            Log-Success "Unit tests passed"
        } else {
            Log-Warning "Some unit tests failed"
        }
    } finally {
        Pop-Location
    }
}

# Function to display summary
function Display-Summary {
    Write-Host ""
    Write-Host "========================================"
    Write-Host "  Test Data Setup Complete"
    Write-Host "========================================"
    Write-Host ""
    
    Log-Info "Infrastructure Status:"
    $redisStatus = if (Test-ContainerRunning "card-fraud-rule-engine-redis") { "Running" } else { "Not Running" }
    $redpandaStatus = if (Test-ContainerRunning "card-fraud-rule-engine-redpanda") { "Running" } else { "Not Running" }
    Write-Host "  - Redis: $redisStatus"
    Write-Host "  - Redpanda: $redpandaStatus"
    Write-Host ""
    
    Log-Info "Available Commands:"
    Write-Host "  Start dev server: doppler run --project=$PROJECT --config=local -- mvn quarkus:dev"
    Write-Host "  Run all tests:    doppler run --project=$PROJECT --config=local -- mvn test"
    Write-Host "  Run smoke tests:  mvn test -Psmoke"
    Write-Host "  Stop infra:       docker-compose down"
    Write-Host ""
    
    Log-Info "Test Endpoints:"
    Write-Host "  Health:           http://localhost:8081/health"
    Write-Host "  Swagger UI:       http://localhost:8081/swagger-ui"
    Write-Host "  OpenAPI:          http://localhost:8081/openapi"
    Write-Host ""
    
    Log-Info "Next Steps:"
    Write-Host "  1. Start the dev server (see command above)"
    Write-Host "  2. Bulk-load rulesets via API or run e2e tests"
    Write-Host "  3. Run: .\scripts\e2e_local.ps1 (if available)"
    Write-Host ""
}

# Main execution
function Main {
    if ($Help) {
        Write-Host "Usage: .\setup-test-data.ps1 [OPTIONS]"
        Write-Host ""
        Write-Host "Options:"
        Write-Host "  -SkipBuild    Skip building the application"
        Write-Host "  -SkipTests    Skip running tests"
        Write-Host "  -Help         Show this help message"
        exit 0
    }
    
    Write-Host "========================================"
    Write-Host "  Card Fraud Rule Engine"
    Write-Host "  Test Data Setup Script"
    Write-Host "========================================"
    Write-Host ""
    
    # Check Doppler
    if (-not (Test-Command doppler)) {
        Log-Error "Doppler CLI not found. Please install Doppler."
        exit 1
    }
    
    # Verify Doppler login
    try {
        $null = doppler me --silent 2>$null
    } catch {
        Log-Error "Not logged into Doppler. Please run: doppler login"
        exit 1
    }
    
    # Verify project access
    try {
        $null = doppler secrets --project="$PROJECT" --config=local get REDIS_URL --silent 2>$null
    } catch {
        Log-Error "Cannot access Doppler project '$PROJECT'"
        exit 1
    }
    
    Log-Success "Doppler authentication verified"
    
    # Execute setup steps
    Start-Infrastructure
    Upload-Rulesets
    Seed-Redis
    
    if (-not $SkipBuild) {
        Build-Application
    }
    
    if (-not $SkipTests) {
        Run-Tests
    }
    
    Display-Summary
}

# Run main function
Main
