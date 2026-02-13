#!/bin/bash
# Wrapper script to run load tests from card-fraud-rule-engine directory
# This script navigates to the sibling card-fraud-e2e-load-testing repository
# and executes the load test with provided parameters.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
USERS=1000
SPAWN_RATE=100
RUN_TIME=5m
AUTH_MODE="none"
SCENARIO=""
HEADLESS=true
RUN_ID=""

# Path to sibling load testing repository
LOAD_TEST_REPO="../card-fraud-e2e-load-testing"

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Run load tests against the rule engine using the card-fraud-e2e-load-testing repository.

Options:
  -u, --users N              Number of concurrent users (default: 1000)
  -s, --spawn-rate N         Spawn rate per second (default: 100)
  -t, --run-time DURATION     Run duration (default: 5m)
  -a, --auth-mode MODE       Authentication mode: none|auth0|local (default: none)
  -c, --scenario SCENARIO     Test scenario: smoke|baseline|stress|soak|spike
  -w, --web                  Run with web UI (headless mode by default)
  -r, --run-id ID             Custom run ID for tracking
  -h, --help                 Show this help message

Environment Variables:
  RULE_ENGINE_URL            Rule engine URL (default: http://localhost:8081)
  AUTH0_DOMAIN               Auth0 domain (for auth0 mode)
  AUTH0_AUDIENCE             Auth0 audience (for auth0 mode)
  AUTH0_CLIENT_ID            Auth0 client ID (for auth0 mode)
  AUTH0_CLIENT_SECRET        Auth0 client secret (for auth0 mode)

Examples:
  # Quick smoke test
  $0 --users 50 --run-time 2m --scenario smoke

  # Full load test with web UI
  $0 --users 1000 --spawn-rate 100 --run-time 10m --web

  # Auth0 authenticated test
  $0 --users 1000 --auth-mode auth0

  # Local development (no JWT)
  $0 --users 500 --auth-mode none

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--users)
            USERS="$2"
            shift 2
            ;;
        -s|--spawn-rate)
            SPAWN_RATE="$2"
            shift 2
            ;;
        -t|--run-time)
            RUN_TIME="$2"
            shift 2
            ;;
        -a|--auth-mode)
            AUTH_MODE="$2"
            shift 2
            ;;
        -c|--scenario)
            SCENARIO="--scenario $2"
            shift 2
            ;;
        -w|--web)
            HEADLESS=false
            shift
            ;;
        -r|--run-id)
            RUN_ID="--run-id $2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

# Check if load testing repository exists
if [ ! -d "$LOAD_TEST_REPO" ]; then
    echo -e "${RED}Error: Load testing repository not found at $LOAD_TEST_REPO${NC}"
    echo "Please clone the repository:"
    echo "  git clone https://github.com/your-org/card-fraud-e2e-load-testing.git ../card-fraud-e2e-load-testing"
    exit 1
fi

# Set default RULE_ENGINE_URL if not set
export RULE_ENGINE_URL="${RULE_ENGINE_URL:-http://localhost:8081}"

# Display test configuration
echo -e "${GREEN}=== Rule Engine Load Test ===${NC}"
echo "Target: $RULE_ENGINE_URL"
echo "Users: $USERS"
echo "Spawn Rate: $SPAWN_RATE/sec"
echo "Run Time: $RUN_TIME"
echo "Auth Mode: $AUTH_MODE"
if [ -n "$SCENARIO" ]; then
    echo "Scenario: $SCENARIO"
fi
echo ""

# Navigate to load testing repository and run test
echo -e "${YELLOW}Navigating to $LOAD_TEST_REPO${NC}"
cd "$LOAD_TEST_REPO"

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo -e "${YELLOW}uv not found. Installing...${NC}"
    curl -sSL https://astral.sh/uv | bash
    export PATH="$HOME/.local/bin:$PATH"
fi

# Build command
if [ "$HEADLESS" = true ]; then
    echo -e "${YELLOW}Running headless load test...${NC}"

    uv run lt-rule-engine \
        --users "$USERS" \
        --spawn-rate "$SPAWN_RATE" \
        --run-time "$RUN_TIME" \
        --auth-mode "$AUTH_MODE" \
        $SCENARIO \
        $RUN_ID \
        --headless
else
    echo -e "${YELLOW}Starting web UI at http://localhost:8089${NC}"
    echo "Press Ctrl+C to stop the test"

    uv run lt-rule-engine \
        --users "$USERS" \
        --spawn-rate "$SPAWN_RATE" \
        --auth-mode "$AUTH_MODE" \
        $SCENARIO \
        $RUN_ID
fi

# Return to original directory
cd - > /dev/null

echo -e "${GREEN}Load test complete!${NC}"
echo "Reports available in: $LOAD_TEST_REPO/html-reports/"
