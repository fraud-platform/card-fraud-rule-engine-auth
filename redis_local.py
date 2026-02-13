#!/usr/bin/env python3
"""
Local Redis Management

Provides uv scripts for managing the local Redis container.
Checks for shared platform infrastructure first (card-fraud-platform),
falls back to local docker-compose if not available.

Usage:
    uv run redis-local-up           # Start Redis
    uv run redis-local-down         # Stop Redis
    uv run redis-local-reset        # Stop and remove data
    uv run redis-local-verify       # Verify connectivity
"""

import subprocess
import sys

from cli._runner import run

# Container names: shared platform vs local fallback
PLATFORM_CONTAINER = "card-fraud-redis"
LOCAL_CONTAINER = "card-fraud-redis"  # Updated to match platform naming


def _is_platform_container_running() -> bool:
    """Check if the shared platform Redis container is already running."""
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{.State.Status}}", PLATFORM_CONTAINER],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "running"


def up() -> None:
    """Start Redis container (uses shared platform if available)."""
    if _is_platform_container_running():
        print(f"[OK] Redis already running via shared platform ({PLATFORM_CONTAINER})")
        print("     Managed by: card-fraud-platform")
        print("     Endpoint: redis://localhost:6379")
        return
    run(["docker", "compose", "-f", "docker-compose.yml", "up", "-d", "redis"])


def down() -> None:
    """Stop Redis containers without removing data."""
    if _is_platform_container_running():
        print(f"[INFO] Redis is managed by card-fraud-platform ({PLATFORM_CONTAINER})")
        print("       To stop: cd ../card-fraud-platform && uv run platform-down")
        return
    run(["docker", "compose", "-f", "docker-compose.yml", "stop", "redis"])


def reset() -> None:
    """Stop Redis containers and remove all data."""
    run(["docker", "compose", "-f", "docker-compose.yml", "rm", "-f", "-v", "redis"])


def verify() -> int:
    """Verify Redis setup and connectivity.

    Usage:
        uv run redis-local-verify
    """
    container = PLATFORM_CONTAINER

    print("\n[1/2] Checking Redis container status...")

    # Check platform container first, then local
    if _is_platform_container_running():
        print(f"[OK] Redis running via shared platform ({container})")
    else:
        result = subprocess.run(
            ["docker", "compose", "-f", "docker-compose.yml", "ps", "redis"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0 or "redis" not in result.stdout:
            print("[ERROR] Redis container is not running")
            print("   Start via platform: cd ../card-fraud-platform && uv run platform-up")
            print("   Start locally:      uv run redis-local-up")
            return 1
        print(f"[OK] Redis running via local compose ({container})")

    print("\n[2/2] Testing Redis connection...")
    result = subprocess.run(
        ["docker", "exec", container, "redis-cli", "ping"],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0 and result.stdout.strip() == "PONG":
        print("[OK] Redis PING successful")

        result = subprocess.run(
            ["docker", "exec", container, "redis-cli", "info", "server"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            for line in result.stdout.split("\n"):
                if line.startswith("redis_version") or line.startswith("os"):
                    print(f"   {line}")

        print("\n" + "=" * 60)
        print("REDIS SETUP VERIFIED")
        print("=" * 60)
        print("Endpoint: redis://localhost:6379")
        print("\nNext steps:")
        print("  - Start dev server: uv run doppler-local")
        print("  - Run tests: uv run doppler-local-test")
        print("  - Stop Redis: uv run redis-local-down")
        return 0
    else:
        print("[ERROR] Redis PING failed")
        print(f"   Output: {result.stdout}")
        print(f"   Error: {result.stderr}")
        return 1


def infra_up() -> None:
    """Start all local infrastructure (Redis + Redpanda)."""
    if _is_platform_container_running():
        print("[OK] Infrastructure already running via shared platform")
        print("     Managed by: card-fraud-platform")
        return
    run(["docker", "compose", "-f", "docker-compose.yml", "up", "-d"])


def infra_down() -> None:
    """Stop all local infrastructure."""
    run(["docker", "compose", "-f", "docker-compose.yml", "down"])


def main() -> int:
    """Default entry point - starts Redis."""
    up()
    return 0


# Aliases for pyproject.toml entry points
redis_up = up
redis_down = down


if __name__ == "__main__":
    sys.exit(main())
