#!/bin/bash
# Card Fraud Rule Engine - Test Data Setup Script
# Session 5.1: Automated test data setup for local development

set -e

PROJECT="card-fraud-rule-engine"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to check if Docker container is running
container_running() {
    docker ps --format '{{.Names}}' | grep -q "$1"
}

# Function to start infrastructure
start_infrastructure() {
    log_info "Starting local infrastructure..."
    
    # Check Docker
    if ! command_exists docker; then
        log_error "Docker not found. Please install Docker."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker is not running. Please start Docker."
        exit 1
    fi
    
    # Start all services from docker-compose.yml
    docker-compose up -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to start..."
    sleep 5
    
    # Check Redis
    if container_running "card-fraud-rule-engine-redis"; then
        if docker exec card-fraud-rule-engine-redis redis-cli ping | grep -q PONG; then
            log_success "Redis is healthy"
        else
            log_error "Redis is not responding"
            exit 1
        fi
    else
        log_error "Redis container is not running"
        exit 1
    fi
    
    # Check Redpanda
    if container_running "card-fraud-rule-engine-redpanda"; then
        log_success "Redpanda is running"
    else
        log_warning "Redpanda container is not running (optional)"
    fi
    
    log_success "Infrastructure started successfully"
}

# Function to upload sample rulesets
upload_rulesets() {
    log_info "Uploading sample rulesets to MinIO..."
    
    # Check if MinIO is accessible
    if ! curl -s "$S3_ENDPOINT_URL/minio/health/live" > /dev/null 2>&1; then
        log_warning "MinIO is not accessible. Rulesets must be uploaded from rule-management project."
        log_info "To upload rulesets, run from card-fraud-rule-management:"
        log_info "  uv run objstore-local-up"
        log_info "  cd ../card-fraud-rule-engine"
        log_info "  python scripts/upload_sample_ruleset.py"
        return 0
    fi
    
    # Run the Python upload script
    if command_exists python3; then
        python3 "$SCRIPT_DIR/upload_sample_ruleset.py"
    elif command_exists python; then
        python "$SCRIPT_DIR/upload_sample_ruleset.py"
    else
        log_warning "Python not found. Skipping ruleset upload."
    fi
}

# Function to seed Redis with test data
seed_redis() {
    log_info "Seeding Redis with test data..."
    
    # Create some velocity test data
    local test_cards=("test-card-001" "test-card-002" "test-card-003")
    
    for card in "${test_cards[@]}"; do
        # Initialize velocity counters for testing
        docker exec card-fraud-rule-engine-redis redis-cli \
            EVAL "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], 3600) end; return count" \
            1 "vel:global:card_hash:$card" 2>/dev/null || true
    done
    
    log_success "Redis test data seeded"
}

# Function to build the application
build_application() {
    log_info "Building application..."
    
    if ! command_exists mvn; then
        log_warning "Maven not found. Skipping build."
        return 0
    fi
    
    cd "$SCRIPT_DIR/.."
    mvn clean package -DskipTests -q
    
    log_success "Application built successfully"
}

# Function to run tests
run_tests() {
    log_info "Running tests to verify setup..."
    
    cd "$SCRIPT_DIR/.."
    
    # Run smoke tests first
    if mvn test -Psmoke -q 2>/dev/null; then
        log_success "Smoke tests passed"
    else
        log_warning "Some smoke tests failed (this is OK if app is not running)"
    fi
    
    # Run unit tests
    if mvn test -q 2>/dev/null; then
        log_success "Unit tests passed"
    else
        log_warning "Some unit tests failed"
    fi
}

# Function to display summary
display_summary() {
    echo ""
    echo "========================================"
    echo "  Test Data Setup Complete"
    echo "========================================"
    echo ""
    log_info "Infrastructure Status:"
    echo "  - Redis: $(container_running 'card-fraud-rule-engine-redis' && echo 'Running' || echo 'Not Running')"
    echo "  - Redpanda: $(container_running 'card-fraud-rule-engine-redpanda' && echo 'Running' || echo 'Not Running')"
    echo ""
    log_info "Available Commands:"
    echo "  Start dev server: doppler run --project=$PROJECT --config=local -- mvn quarkus:dev"
    echo "  Run all tests:    doppler run --project=$PROJECT --config=local -- mvn test"
    echo "  Run smoke tests:  mvn test -Psmoke"
    echo "  Stop infra:       docker-compose down"
    echo ""
    log_info "Test Endpoints:"
    echo "  Health:           http://localhost:8081/health"
    echo "  Swagger UI:       http://localhost:8081/swagger-ui"
    echo "  OpenAPI:          http://localhost:8081/openapi"
    echo ""
    log_info "Next Steps:"
    echo "  1. Start the dev server (see command above)"
    echo "  2. Bulk-load rulesets via API or run e2e tests"
    echo "  3. Run: ./scripts/e2e_local.sh (if available)"
    echo ""
}

# Main execution
main() {
    echo "========================================"
    echo "  Card Fraud Rule Engine"
    echo "  Test Data Setup Script"
    echo "========================================"
    echo ""
    
    # Check Doppler
    if ! command_exists doppler; then
        log_error "Doppler CLI not found. Please install Doppler."
        exit 1
    fi
    
    # Verify Doppler login
    if ! doppler me --silent 2>/dev/null; then
        log_error "Not logged into Doppler. Please run: doppler login"
        exit 1
    fi
    
    # Verify project access
    if ! doppler secrets --project="$PROJECT" --config=local get REDIS_URL --silent 2>/dev/null; then
        log_error "Cannot access Doppler project '$PROJECT'"
        exit 1
    fi
    
    log_success "Doppler authentication verified"
    
    # Parse command line arguments
    SKIP_BUILD=false
    SKIP_TESTS=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-build    Skip building the application"
                echo "  --skip-tests    Skip running tests"
                echo "  --help          Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Execute setup steps
    start_infrastructure
    upload_rulesets
    seed_redis
    
    if [ "$SKIP_BUILD" = false ]; then
        build_application
    fi
    
    if [ "$SKIP_TESTS" = false ]; then
        run_tests
    fi
    
    display_summary
}

# Run main function
main "$@"
