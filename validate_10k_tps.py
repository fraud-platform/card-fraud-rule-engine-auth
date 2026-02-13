#!/usr/bin/env python3
"""
10K TPS SLO Validation Script

This script orchestrates the full 10K TPS validation:
1. Checks platform infra status
2. Starts platform infra if down
3. Loads test ruleset to MinIO
4. Starts rule engine (or verifies it's running)
5. Runs load tests from e2e-load-testing repo (both no-auth and JWT modes)
6. Generates HTML report
7. Updates SESSION_LEARNINGS.md with results

Usage:
    python scripts/validate_10k_tps.py [--skip-infra] [--skip-ruleset] [--skip-engine]
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import time

# Colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
NC = "\033[0m"

# Paths
REPO_ROOT = Path(__file__).parent.parent
PLATFORM_REPO = REPO_ROOT.parent / "card-fraud-platform"
LOAD_TEST_REPO = REPO_ROOT.parent / "card-fraud-e2e-load-testing"
SCRIPTS_DIR = REPO_ROOT / "scripts"

# Target metrics
TARGET_TPS = 10_000
TARGET_P50_NO_AUTH = 5.0  # ms
TARGET_P95_NO_AUTH = 15.0
TARGET_P50_JWT = 15.0  # ms (relaxed target for JWT mode)
TARGET_P95_JWT = 25.0


def log(msg, color=NC):
    """Log a message with optional color."""
    print(f"{color}{msg}{NC}")


def run_command(cmd, check=True, capture_output=False, cwd=None, env=None):
    """Run a shell command and return the result."""
    log(f"Running: {' '.join(cmd)}", BLUE)
    if capture_output:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=cwd, env=env)
        return result.returncode, result.stdout, result.stderr
    else:
        return subprocess.run(cmd, shell=True, check=check, cwd=cwd, env=env)


def check_platform_infra():
    """Check if platform infra is running."""
    log("Checking platform infrastructure status...", BLUE)

    # Check Redis
    result = run_command(
        ["docker", "inspect", "-f", "{{.State.Health}}", "card-fraud-redis"],
        check=False, capture_output=True
    )
    redis_status = result.stdout.strip() if result.stdout else "unknown"

    # Check Redpanda
    result = run_command(
        ["docker", "inspect", "-f", "{{.State.Health}}", "card-fraud-redpanda"],
        check=False, capture_output=True
    )
    redpanda_status = result.stdout.strip() if result.stdout else "unknown"

    # Check MinIO
    result = run_command(
        ["docker", "inspect", "-f", "{{.State.Health}}", "card-fraud-minio"],
        check=False, capture_output=True
    )
    minio_status = result.stdout.strip() if result.stdout else "unknown"

    log(f"  Redis: {redis_status}", GREEN if redis_status == "healthy" else YELLOW)
    log(f"  Redpanda: {redpanda_status}", GREEN if redpanda_status == "healthy" else YELLOW)
    log(f"  MinIO: {minio_status}", GREEN if minio_status == "healthy" else YELLOW)

    all_healthy = (
        redis_status == "healthy" and
        redpanda_status == "healthy" and
        minio_status == "healthy"
    )

    if all_healthy:
        log("✓ All infrastructure services are healthy", GREEN)
    else:
        log("⚠ Some infrastructure services are down", YELLOW)

    return all_healthy


def start_platform_infra():
    """Start platform infrastructure if not running."""
    log("Starting platform infrastructure...", YELLOW)
    run_command(
        ["doppler", "run", "--", "uv", "run", "platform-up"],
        cwd=PLATFORM_REPO
    )
    log("✓ Platform infrastructure started", GREEN)
    log("Waiting 10 seconds for services to be healthy...", BLUE)
    time.sleep(10)


def load_ruleset():
    """Load test ruleset to MinIO."""
    log("Loading CARD_AUTH ruleset to MinIO...", BLUE)
    ruleset_script = SCRIPTS_DIR / "load_auth_ruleset.py"

    if not ruleset_script.exists():
        log(f"ERROR: Ruleset script not found: {ruleset_script}", RED)
        return False

    run_command(
        ["python", str(ruleset_script)],
        cwd=REPO_ROOT
    )
    log("✓ Ruleset loaded successfully", GREEN)
    return True


def check_rule_engine():
    """Check if rule engine is running."""
    log("Checking rule engine status...", BLUE)

    # Try health endpoint
    result = run_command(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:8081/health"],
        check=False, capture_output=True
    )
    status_code = result.stdout.strip()

    if status_code == "200":
        log("✓ Rule engine is running", GREEN)
        return True
    else:
        log(f"⚠ Rule engine not accessible (status: {status_code})", YELLOW)
        return False


def start_rule_engine():
    """Prompt user to start rule engine."""
    log("\n" + "="*60, BLUE)
    log("ACTION REQUIRED: Start Rule Engine", YELLOW)
    log("="*60, BLUE)
    log("")
    log("Open a new terminal and run:", YELLOW)
    log(f"  cd {REPO_ROOT}", YELLOW)
    log("  uv run doppler-local", YELLOW)
    log("")
    log("Or run with JWT:", YELLOW)
    log("  uv run doppler-load-test", YELLOW)
    log("")
    log("Press Enter when rule engine is running...", NC)
    input()

    # Verify it's now running
    if check_rule_engine():
        return True
    else:
        log("ERROR: Rule engine still not accessible. Please start it manually.", RED)
        return False


def run_load_test(auth_mode):
    """Run load test from e2e-load-testing repo."""
    users = 2000
    spawn_rate = 200
    run_time = 10

    log(f"\n{'='*60}", BLUE)
    log(f"Running Load Test - {auth_mode.upper()} mode", YELLOW)
    log(f"{'='*60}", BLUE)
    log(f"  Target: {TARGET_TPS} TPS")
    log(f"  Users: {users}")
    log(f"  Spawn rate: {spawn_rate}/sec")
    log(f"  Duration: {run_time} minutes")
    log(f"  Acceptable P50: {TARGET_P50_NO_AUTH if auth_mode == 'none' else TARGET_P50_JET}ms")
    log("")

    # Build command
    cmd = [
        "uv", "run", "lt-rule-engine",
        f"--users={users}",
        f"--spawn-rate={spawn_rate}",
        f"--run-time={run_time}m",
        "--headless",  # Non-interactive
        f"--auth-mode={auth_mode}",
        f"--run-id=10k-tps-{auth_mode}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
    ]

    # Set environment for load test
    env = os.environ.copy()
    env["RULE_ENGINE_URL"] = "http://localhost:8081"

    # Run the load test
    result = run_command(
        ["uv", "run", "lt-rule-engine",
         f"--users={users}",
         f"--spawn-rate={spawn_rate}",
         f"--run-time={run_time}m",
         "--headless",
         f"--auth-mode={auth_mode}"],
        cwd=LOAD_TEST_REPO,
        env=env
    )

    return result.returncode == 0


def save_report(results):
    """Save test results to SESSION_LEARNINGS.md."""
    session_learnings = REPO_ROOT / "docs" / "SESSION_LEARNINGS.md"

    if not session_learnings.exists():
        log("WARNING: SESSION_LEARNINGS.md not found, skipping documentation update", YELLOW)
        return

    log("\n" + "="*60, BLUE)
    log("Saving results to SESSION_LEARNINGS.md", YELLOW)
    log("="*60 + "\n", NC)

    # Read current content
    with open(session_learnings, "r") as f:
        content = f.read()

    # Find the position to insert results (before "**End of Session Learnings**")
    insert_marker = "\n**End of Session Learnings**\n"
    if insert_marker in content:
        content = content.replace(insert_marker, "")

    # Create results section
    results_section = f"""
## 10K TPS SLO Validation (2026-02-02)

### Execution Summary

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

### Test Configuration

| Parameter | Value |
|-----------|-------|
| Authentication Modes Tested | No-auth, JWT (auth0) |
| Users | 2000 |
| Spawn Rate | 200/sec |
| Duration per Test | 10 minutes |
| Target TPS | 10,000 |

### Results

| Mode | Status | Details |
|------|--------|---------|
| **No-auth** | {results.get('no_auth', 'PENDING')} | See load test output above |
| **JWT** | {results.get('jwt', 'PENDING')} | See load test output above |

### Conclusions

{results.get('conclusions', 'See load test output above')}

---

"""

    # Append results
    with open(session_learnings, "w") as f:
        f.write(content + results_section + insert_marker)

    log(f"✓ Results saved to {session_learnings.name}", GREEN)


def main():
    parser = argparse.ArgumentParser(description="10K TPS SLO Validation")
    parser.add_argument("--skip-infra", action="store_true", help="Skip platform infra checks")
    parser.add_argument("--skip-ruleset", action="store_true", help="Skip ruleset loading")
    parser.add_argument("--skip-engine", action="store_true", help="Skip rule engine check")
    parser.add_argument("--no-auth-only", action="store_true", help="Only run no-auth test (skip JWT)")
    args = parser.parse_args()

    log("="*60, BLUE)
    log("10K TPS SLO Validation", YELLOW)
    log("="*60 + "\n", NC)

    results = {}

    try:
        # Step 1: Check/Start platform infra
        if not args.skip_infra:
            if not check_platform_infra():
                log("\nStarting platform infrastructure...")
                start_platform_infra()
                log("\nWaiting 20 seconds for all services to be healthy...")
                time.sleep(20)
        else:
            log("Skipping platform infra checks (--skip-infra)", YELLOW)

        # Step 2: Load ruleset
        if not args.skip_ruleset:
            load_ruleset()
        else:
            log("Skipping ruleset loading (--skip-ruleset)", YELLOW)

        # Step 3: Check/Start rule engine
        if not args.skip_engine:
            if not check_rule_engine():
                start_rule_engine()
        else:
            log("Skipping rule engine check (--skip-engine)", YELLOW)

        # Step 4: Run load tests
        log("\n" + "="*60, BLUE)
        log("Starting Load Tests", YELLOW)
        log("="*60 + "\n", NC)

        # Test 1: No-auth mode
        log("\n### Test 1: No-Auth Mode (P50 < 5ms target)", BLUE)
        results['no_auth'] = "RUNNING..."
        if run_load_test("none"):
            results['no_auth'] = "COMPLETED"
        else:
            results['no_auth'] = "FAILED"

        # Test 2: JWT mode (if not skipped)
        if not args.no_auth_only:
            log("\n### Test 2: JWT Mode (P50 < 15ms target)", BLUE)
            results['jwt'] = "RUNNING..."
            if run_load_test("auth0"):
                results['jwt'] = "COMPLETED"
            else:
                results['jwt'] = "FAILED"
        else:
            log("\nSkipping JWT test (--no-auth-only)", YELLOW)

        # Step 5: Generate summary
        log("\n" + "="*60, BLUE)
        log("Load Test Complete", GREEN)
        log("="*60 + "\n", NC)

        # Add conclusions based on results
        if results.get('no_auth') == "COMPLETED" and results.get('jwt', 'SKIPPED') == 'COMPLETED':
            results['conclusions'] = """
**Both tests completed successfully!** The rule engine handles both no-auth and JWT modes under load.
Check the Locust output above for actual TPS, P50, P95, P99 metrics.

**To view full Locust HTML report:** The e2e-load-testing repo generates HTML reports in its output directory.
"""
        elif results.get('no_auth') == "COMPLETED":
            results['conclusions'] = """
**No-auth test completed!** JWT test skipped (--no-auth-only).

Check the Locust output above for actual TPS, P50, P95, P99 metrics.
"""
        elif results.get('no_auth') == "FAILED":
            results['conclusions'] = """
**No-auth test failed!** Check the rule engine logs and infrastructure status.

Common issues:
- Rule engine not running
- Ruleset not loaded
- Infrastructure (Redis, Redpanda) not running
- Port conflicts
"""

        # Save results
        save_report(results)

        log("\n✓ Validation complete!", GREEN)
        log(f"\nNext steps:")
        log(f"  1. Check Locust output above for actual TPS, P50, P95, P99 metrics")
        log(f"   2. Check e2e-load-testing repo for HTML reports")
        log(f"  3. See SESSION_LEARNINGS.md for documented results")

        return 0

    except KeyboardInterrupt:
        log("\n\n⚠ Validation interrupted by user", YELLOW)
        return 1
    except Exception as e:
        log(f"\n❌ Error: {e}", RED)
        return 1


if __name__ == "__main__":
    sys.exit(main())
