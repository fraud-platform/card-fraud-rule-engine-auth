"""Test Data Setup Script

Loads rulesets into a running fraud rule engine instance via the bulk-load API.
Requires Auth0 credentials from Doppler environment variables.
"""

import os
import sys

import httpx


BASE_URL = os.getenv("FRAUD_ENGINE_BASE_URL", "http://localhost:8081")
AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://fraud-rule-engine-api")


def _check_env() -> tuple[str, str, str]:
    """Get required Auth0 credentials from environment."""
    domain = os.getenv("AUTH0_DOMAIN")
    client_id = os.getenv("AUTH0_CLIENT_ID")
    client_secret = os.getenv("AUTH0_CLIENT_SECRET")
    if not all([domain, client_id, client_secret]):
        print("ERROR: Missing Auth0 credentials.")
        print("Set AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET")
        sys.exit(1)
    return domain, client_id, client_secret


def get_auth0_token() -> str:
    """Fetch an Auth0 M2M token using environment variables."""
    domain, client_id, client_secret = _check_env()

    response = httpx.post(
        f"https://{domain}/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": AUDIENCE,
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def load_rulesets(token: str) -> int:
    """Load rulesets via the bulk-load API."""
    response = httpx.post(
        f"{BASE_URL}/v1/evaluate/rulesets/bulk-load",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        json={
            "rulesets": [
                {"key": "CARD_AUTH", "version": 1, "country": "global"},
                {"key": "CARD_MONITORING", "version": 1, "country": "global"},
            ]
        },
        timeout=30,
    )
    response.raise_for_status()
    result = response.json()
    loaded = result.get("loaded", 0)
    requested = result.get("requested", 0)
    print(f"Rulesets loaded: {loaded} / {requested}")
    return loaded


def get_registry_status(token: str) -> dict | None:
    """Get the current ruleset registry status."""
    try:
        response = httpx.get(
            f"{BASE_URL}/v1/evaluate/rulesets/registry/status",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
        count = result.get("count", 0)
        rulesets = result.get("rulesets", [])
        print(f"\nRegistry status: {count} rulesets loaded")
        for rs in rulesets:
            print(f"  - {rs['key']} v{rs.get('version', '?')}")
        return result
    except httpx.HTTPError as e:
        print(f"Warning: Could not get registry status: {e}")
        return None


def main():
    """Main entry point."""
    print("Test Data Setup for Card Fraud Rule Engine")
    print(f"Target: {BASE_URL}\n")

    # Check if engine is running
    try:
        httpx.get(f"{BASE_URL}/health/ready", timeout=5)
    except httpx.HTTPError as e:
        print(f"ERROR: Cannot connect to engine at {BASE_URL}")
        print(f"Detail: {e}")
        print("\nPlease start the engine first:")
        print("  uv run infra-local-up    # Start Redis + Redpanda")
        print("  uv run doppler-local     # Start engine with Doppler secrets")
        sys.exit(1)

    # Get Auth0 token
    print("Fetching Auth0 token...")
    token = get_auth0_token()
    print("Token obtained.")

    # Show current registry status
    get_registry_status(token)

    # Load rulesets
    print("\nLoading rulesets...")
    loaded = load_rulesets(token)

    if loaded > 0:
        print("\nTest data setup complete!")
    else:
        print("\nWarning: No rulesets were loaded.")
        print("The engine may be using YAML fallback rulesets.")

    # Show final registry status
    print()
    get_registry_status(token)


if __name__ == "__main__":
    main()
