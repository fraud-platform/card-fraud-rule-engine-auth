"""
E2E Test Configuration and Fixtures

Supports two modes:
  1. NO-AUTH mode (default for local dev):
     - Server running in dev mode (uv run doppler-local) with JWT disabled
     - No Auth0 calls needed
     - Set E2E_AUTH_MODE=none or just don't set AUTH0_DOMAIN

  2. JWT mode (for production-like testing):
     - Server running with JWT enabled (uv run doppler-load-test)
     - Fetches ONE Auth0 token per session and caches it
     - Set E2E_AUTH_MODE=jwt and AUTH0_* env vars

Usage:
    # No-auth mode (test against dev server)
    uv run test-e2e-no-auth

    # JWT mode (test against load-test server)
    uv run test-e2e
"""

import os
import uuid
from typing import Generator

import httpx
import pytest

BASE_URL = os.getenv("FRAUD_ENGINE_BASE_URL", "http://localhost:8081")

# Auth mode: "jwt" or "none"
AUTH_MODE = os.getenv("E2E_AUTH_MODE", "none").lower()

# Module-level token cache (fetched once, reused for entire session)
_cached_token: str | None = None


def _is_jwt_mode() -> bool:
    """Check if JWT authentication is enabled for E2E tests."""
    if AUTH_MODE == "jwt":
        return True
    # Auto-detect: if AUTH0_DOMAIN is set, use JWT mode
    if AUTH_MODE != "none" and os.getenv("AUTH0_DOMAIN"):
        return True
    return False


def _fetch_auth0_token() -> str:
    """
    Fetch a real Auth0 M2M token using environment variables.
    Token is cached at module level - only ONE call per test session.
    """
    global _cached_token
    if _cached_token is not None:
        return _cached_token

    domain = os.getenv("AUTH0_DOMAIN")
    client_id = os.getenv("AUTH0_CLIENT_ID")
    client_secret = os.getenv("AUTH0_CLIENT_SECRET")
    audience = os.getenv("AUTH0_AUDIENCE", "https://fraud-rule-engine-api")

    if not all([domain, client_id, client_secret]):
        pytest.skip(
            "Auth0 credentials not configured. "
            "Set AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET."
        )

    response = httpx.post(
        f"https://{domain}/oauth/token",
        headers={"content-type": "application/json"},
        json={
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": audience,
            "grant_type": "client_credentials",
        },
        timeout=10.0,
    )
    response.raise_for_status()
    _cached_token = response.json()["access_token"]
    return _cached_token


@pytest.fixture(scope="session")
def base_url() -> str:
    return BASE_URL


@pytest.fixture(scope="session")
def auth_mode() -> str:
    return "jwt" if _is_jwt_mode() else "none"


@pytest.fixture(scope="session")
def auth_token() -> str | None:
    """Return cached Auth0 M2M JWT token, or None in no-auth mode."""
    if _is_jwt_mode():
        return _fetch_auth0_token()
    return None


@pytest.fixture(scope="function")
def client(auth_token: str | None) -> Generator[httpx.Client, None, None]:
    """
    Authenticated HTTP client.
    - JWT mode: includes Bearer token
    - No-auth mode: plain client (server has JWT disabled)
    """
    headers = {"Content-Type": "application/json"}
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"

    with httpx.Client(base_url=BASE_URL, headers=headers, timeout=30.0) as c:
        yield c


@pytest.fixture(scope="function")
def unauth_client() -> Generator[httpx.Client, None, None]:
    """Unauthenticated HTTP client (no Bearer token)."""
    headers = {"Content-Type": "application/json"}
    with httpx.Client(base_url=BASE_URL, headers=headers, timeout=30.0) as c:
        yield c


@pytest.fixture(scope="function")
def test_transaction_id() -> str:
    return f"e2e-test-{uuid.uuid4()}"


@pytest.fixture(scope="function")
def test_card_hash() -> str:
    return f"e2e-card-{uuid.uuid4()}"


def requires_jwt(func):
    """Decorator to skip tests that require JWT when in no-auth mode."""
    return pytest.mark.skipif(
        not _is_jwt_mode(),
        reason="Requires JWT mode (E2E_AUTH_MODE=jwt)"
    )(func)


def requires_no_auth(func):
    """Decorator to skip tests that only work without JWT."""
    return pytest.mark.skipif(
        _is_jwt_mode(),
        reason="Only works in no-auth mode (server JWT disabled)"
    )(func)
