"""E2E Test Runner

Runs end-to-end tests against a running fraud rule engine instance.
Uses Doppler to inject Auth0 credentials for authenticated requests.
"""

import os
import sys

import httpx


def _check_engine(base_url: str) -> bool:
    """Check if the engine is running and healthy."""
    try:
        response = httpx.get(f"{base_url}/health/ready", timeout=2.0)
        return response.status_code == 200
    except Exception:
        return False


def main():
    """Run E2E tests with Doppler environment variables."""
    from cli._runner import run

    base_url = os.getenv("FRAUD_ENGINE_BASE_URL", "http://localhost:8081")

    print(f"Running E2E tests against: {base_url}")
    print("Start with: uv run doppler-local\n")

    if not _check_engine(base_url):
        print(f"Error: Cannot connect to engine at {base_url}")
        print("\nPlease start the engine first:")
        print("  uv run infra-local-up    # Start Redis + Redpanda")
        print("  uv run doppler-local     # Start engine with Doppler secrets")
        sys.exit(1)

    run([sys.executable, "-m", "pytest", "e2e/", "-v", "--tb=short"])


if __name__ == "__main__":
    main()
