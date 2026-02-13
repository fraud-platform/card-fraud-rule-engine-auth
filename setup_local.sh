#!/bin/bash
# card-fraud-rule-engine - Doppler Local Development Setup (Bash)
# This script sets up local environment with Doppler secrets

set -e

PROJECT="card-fraud-rule-engine"

echo "=== Card Fraud Rule Engine Local Setup ==="
echo ""

# Check Doppler is installed
if ! command -v doppler &> /dev/null; then
    echo "Doppler CLI not found. Installing..."
    curl -Ls https://cli.doppler.com/install.sh | bash
fi

# Verify Doppler login
echo "Verifying Doppler login..."
doppler me --silent || doppler login

# Verify project access
echo "Verifying access to project: $PROJECT"
doppler secrets --project="$PROJECT" --config=local get REDIS_URL --silent || {
    echo "ERROR: Cannot access Doppler project '$PROJECT'"
    echo "Please ensure you have access to the Doppler project."
    exit 1
}

echo ""
echo "=== Doppler Secrets Configuration ==="
echo ""
echo "Local config secrets:"
doppler secrets --project="$PROJECT" --config=local | grep -E "^(REDIS_URL|DATABASE_URL|AUTH0_DOMAIN|AUTH0_AUDIENCE|RULE_MANAGEMENT_URL)=" || true
echo ""

echo "=== Starting Local Infrastructure ==="
echo ""

# Check if Docker is running
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker not found. Please install Docker."
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "ERROR: Docker is not running. Please start Docker."
    exit 1
fi

# Start Redis if not running
if ! docker ps --format '{{.Names}}' | grep -q "card-fraud-rule-engine-redis"; then
    echo "Starting Redis..."
    docker-compose up -d redis
    echo "Redis started on localhost:6379"
else
    echo "Redis is already running"
fi

echo ""
echo "=== Development Server ==="
echo ""
echo "To start the Quarkus dev server with Doppler secrets:"
echo "  doppler run --project=$PROJECT --config=local -- mvn quarkus:dev"
echo ""

echo "=== Verification ==="
echo ""
echo "Testing Redis connection..."
if docker exec card-fraud-rule-engine-redis redis-cli ping | grep -q PONG; then
    echo "✓ Redis is healthy"
else
    echo "✗ Redis connection failed"
    exit 1
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Review Doppler secrets: doppler secrets --project=$PROJECT --config=local"
echo "2. Start dev server: doppler run --project=$PROJECT --config=local -- mvn quarkus:dev"
echo "3. Run tests: doppler run --project=$PROJECT --config=local -- mvn test"
