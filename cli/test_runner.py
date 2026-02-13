"""
Unified test runner for Card Fraud Rule Engine.

Simple commands for running all types of tests locally.
All commands go through Doppler for secrets management.

Usage:
    uv run test-unit              # Unit profile (485 tests as of 2026-02-03)
    uv run test-smoke             # Quick smoke tests (needs Redis)
    uv run test-integration       # Integration tests (needs Redis)
    uv run test-all               # Unit + smoke + integration
    uv run test-e2e               # E2E with JWT auth (needs running server)
    uv run test-e2e-no-auth       # E2E without JWT (needs server in dev mode)
    uv run test-load              # Start load test server (JWT enabled)
    uv run test-load-no-auth      # Start load test server (no JWT)
    uv run test-coverage          # Unit tests + Jacoco coverage report
"""

from __future__ import annotations

import os
import subprocess
import sys

_DOPPLER_PROJECT = "card-fraud-rule-engine"


def _doppler_prefix(config: str = "local") -> list[str]:
    return [
        "doppler", "run",
        "--project", _DOPPLER_PROJECT,
        f"--config={config}",
        "--",
    ]


def _mvn(args: list[str], doppler: bool = True) -> None:
    """Run Maven with optional Doppler wrapping."""
    cmd = _doppler_prefix() + ["mvn", "-B"] + args if doppler else ["mvn", "-B"] + args
    result = subprocess.run(cmd)
    raise SystemExit(result.returncode)


def _check_redis() -> bool:
    """Check if Redis is reachable."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("localhost", 6379))
        sock.close()
        return True
    except (socket.error, OSError):
        return False


def _check_server(base_url: str = "http://localhost:8081") -> bool:
    """Check if the fraud engine server is running."""
    try:
        import urllib.request
        urllib.request.urlopen(f"{base_url}/health/ready", timeout=3)
        return True
    except Exception:
        return False


def _require_redis():
    """Exit with helpful message if Redis is not running."""
    if not _check_redis():
        print("ERROR: Redis is not running on localhost:6379")
        print("Start it with: uv run redis-local-up")
        sys.exit(1)


def _require_server(base_url: str = "http://localhost:8081"):
    """Exit with helpful message if server is not running."""
    if not _check_server(base_url):
        print(f"ERROR: Fraud engine is not running at {base_url}")
        print("Start it with one of:")
        print("  uv run doppler-local          # Dev mode (no JWT)")
        print("  uv run doppler-load-test      # Load test mode (JWT enabled)")
        sys.exit(1)


# ============================================================
# Java/Maven test commands
# ============================================================

def test_unit() -> None:
    """Run unit-profile tests with Doppler secrets (needs Redis)."""
    _require_redis()
    _mvn(["clean", "test"])


def test_smoke() -> None:
    """Run smoke tests (4 tests, needs Redis)."""
    _require_redis()
    _mvn(["clean", "test", "-Psmoke"])


def test_integration() -> None:
    """Run integration-profile tests with Doppler secrets (needs Redis)."""
    _require_redis()
    _mvn(["clean", "test", "-Pintegration"])


def test_all() -> None:
    """Run unit + smoke + integration tests."""
    _require_redis()
    print("=" * 60)
    print("Running unit tests...")
    print("=" * 60)
    cmd = _doppler_prefix() + ["mvn", "-B", "clean", "test"]
    r1 = subprocess.run(cmd)
    if r1.returncode != 0:
        print("\nUnit tests FAILED")
        raise SystemExit(r1.returncode)

    print("\n" + "=" * 60)
    print("Running smoke tests...")
    print("=" * 60)
    cmd = _doppler_prefix() + ["mvn", "-B", "clean", "test", "-Psmoke"]
    r2 = subprocess.run(cmd)
    if r2.returncode != 0:
        print("\nSmoke tests FAILED")
        raise SystemExit(r2.returncode)

    print("\n" + "=" * 60)
    print("Running integration tests...")
    print("=" * 60)
    cmd = _doppler_prefix() + ["mvn", "-B", "clean", "test", "-Pintegration"]
    r3 = subprocess.run(cmd)
    if r3.returncode != 0:
        print("\nIntegration tests FAILED")
        raise SystemExit(r3.returncode)

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED")
    print("=" * 60)


def test_coverage() -> None:
    """Run unit tests with Jacoco coverage report."""
    _require_redis()
    _mvn(["clean", "test", "jacoco:report"])


# ============================================================
# E2E test commands (Python pytest)
# ============================================================

def test_e2e() -> None:
    """Run E2E tests with JWT auth against running server.

    Requires:
      1. Server running with JWT enabled: uv run doppler-load-test
      2. Doppler secrets available (for Auth0 token)
    """
    base_url = os.getenv("FRAUD_ENGINE_BASE_URL", "http://localhost:8081")
    _require_server(base_url)

    print("Running E2E tests WITH JWT authentication")
    print(f"Target: {base_url}")

    cmd = _doppler_prefix() + [
        sys.executable, "-m", "pytest", "e2e/", "-v", "--tb=short",
    ]
    env = os.environ.copy()
    env["FRAUD_ENGINE_BASE_URL"] = base_url
    env["E2E_AUTH_MODE"] = "jwt"

    result = subprocess.run(cmd, env=env)
    raise SystemExit(result.returncode)


def test_e2e_no_auth() -> None:
    """Run E2E tests WITHOUT JWT auth against running server.

    Requires:
      1. Server running in dev mode: uv run doppler-local
      2. No Auth0 credentials needed
    """
    base_url = os.getenv("FRAUD_ENGINE_BASE_URL", "http://localhost:8081")
    _require_server(base_url)

    print("Running E2E tests WITHOUT JWT authentication")
    print(f"Target: {base_url}")

    cmd = [sys.executable, "-m", "pytest", "e2e/", "-v", "--tb=short"]
    env = os.environ.copy()
    env["FRAUD_ENGINE_BASE_URL"] = base_url
    env["E2E_AUTH_MODE"] = "none"

    result = subprocess.run(cmd, env=env)
    raise SystemExit(result.returncode)


# ============================================================
# Load test commands
# ============================================================

def test_load() -> None:
    """Start load test server with JWT enabled, then run Locust.

    Starts the engine with load-test profile (JWT enabled).
    Locust UI available at http://localhost:8089
    """
    print("To run load tests:")
    print()
    print("  Step 1: Start infrastructure")
    print("    uv run infra-local-up")
    print()
    print("  Step 2: Start engine with JWT (in a separate terminal)")
    print("    uv run doppler-load-test")
    print()
    print("  Step 3: Run Locust (with Doppler for Auth0 credentials)")
    print("    doppler run --project card-fraud-rule-engine --config=local -- "
          "locust -f load-testing/locustfile.py --host=http://localhost:8081")
    print()
    print("  Or headless mode:")
    print("    doppler run --project card-fraud-rule-engine --config=local -- "
          "locust -f load-testing/locustfile.py --host=http://localhost:8081 "
          "--headless -u 50 -r 5 --run-time=2m")
    print()
    print("  Or Docker Compose (all-in-one):")
    print("    doppler run --project card-fraud-rule-engine --config=local -- "
          "docker compose --profile load-testing up")


def test_load_no_auth() -> None:
    """Instructions for load testing without JWT.

    Uses dev mode which disables JWT verification.
    """
    print("To run load tests WITHOUT JWT:")
    print()
    print("  Step 1: Start infrastructure")
    print("    uv run infra-local-up")
    print()
    print("  Step 2: Start engine in dev mode (in a separate terminal)")
    print("    uv run doppler-local")
    print()
    print("  Step 3: Run Locust with NO_AUTH=true")
    print("    NO_AUTH=true locust -f load-testing/locustfile.py "
          "--host=http://localhost:8081")
    print()
    print("  Or headless:")
    print("    NO_AUTH=true locust -f load-testing/locustfile.py "
          "--host=http://localhost:8081 --headless -u 50 -r 5 --run-time=2m")
