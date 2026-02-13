"""Auth0 setup verification script - Rule Engine.

Verifies that Auth0 is correctly configured for this project by checking:
1. API (Resource Server) exists with correct audience
2. API has all expected scopes
3. M2M application exists
4. Client grant exists with correct scopes

NOTE: Rule Engine uses M2M scope-based auth only.
No roles, Actions, or trigger bindings are needed.

Usage:
    uv run auth0-verify
    # or
    doppler run -- python scripts/verify_auth0.py

Exit codes:
    0 - All checks passed
    1 - One or more checks failed
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field

import httpx


EXPECTED_SCOPES = [
    "execute:rules",
    "read:results",
    "replay:transactions",
    "read:metrics",
]


@dataclass
class VerificationResult:
    name: str
    passed: bool
    message: str
    details: list[str] = field(default_factory=list)


class Auth0Verifier:
    def __init__(self, domain: str, token: str, audience: str, m2m_name: str):
        self.domain = domain
        self.audience = audience
        self.m2m_name = m2m_name
        self.client = httpx.Client(
            base_url=f"https://{domain}/api/v2/",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )
        self.results: list[VerificationResult] = []

    def verify_api_exists(self) -> VerificationResult:
        try:
            resp = self.client.get("resource-servers")
            resp.raise_for_status()
            apis = resp.json()

            for api in apis:
                if api.get("identifier") == self.audience:
                    return VerificationResult(
                        name="API Exists",
                        passed=True,
                        message=f"API found: {api.get('name')} ({self.audience})",
                        details=[f"ID: {api.get('id')}"],
                    )

            return VerificationResult(
                name="API Exists",
                passed=False,
                message=f"API with audience '{self.audience}' not found",
                details=[f"Found {len(apis)} APIs, none match expected audience"],
            )
        except Exception as e:
            return VerificationResult(
                name="API Exists",
                passed=False,
                message=f"Error checking API: {e}",
            )

    def verify_api_scopes(self) -> VerificationResult:
        try:
            resp = self.client.get("resource-servers")
            resp.raise_for_status()
            apis = resp.json()

            for api in apis:
                if api.get("identifier") == self.audience:
                    api_scopes = [s.get("value") for s in api.get("scopes", [])]
                    missing = [s for s in EXPECTED_SCOPES if s not in api_scopes]
                    extra = [s for s in api_scopes if s not in EXPECTED_SCOPES]

                    if missing:
                        return VerificationResult(
                            name="API Scopes",
                            passed=False,
                            message=f"Missing {len(missing)} scope(s)",
                            details=[f"Missing: {', '.join(missing)}"]
                            + ([f"Extra: {', '.join(extra)}"] if extra else []),
                        )

                    return VerificationResult(
                        name="API Scopes",
                        passed=True,
                        message=f"All {len(EXPECTED_SCOPES)} expected scopes present",
                        details=[f"Scopes: {', '.join(api_scopes)}"],
                    )

            return VerificationResult(
                name="API Scopes",
                passed=False,
                message="Cannot check scopes - API not found",
            )
        except Exception as e:
            return VerificationResult(
                name="API Scopes",
                passed=False,
                message=f"Error checking scopes: {e}",
            )

    def _find_m2m_client(self) -> dict | None:
        """Find the M2M client by name. Returns client dict or None."""
        try:
            resp = self.client.get("clients")
            resp.raise_for_status()
            for client in resp.json():
                if client.get("name") == self.m2m_name:
                    return client
        except httpx.HTTPError:
            pass
        return None

    def verify_m2m_app_exists(self) -> VerificationResult:
        client = self._find_m2m_client()
        if client:
            app_type = client.get("app_type", "unknown")
            return VerificationResult(
                name="M2M App Exists",
                passed=True,
                message=f"M2M app found: {self.m2m_name}",
                details=[f"Client ID: {client.get('client_id')}", f"App Type: {app_type}"],
            )
        return VerificationResult(
            name="M2M App Exists",
            passed=False,
            message=f"M2M app '{self.m2m_name}' not found",
            details=["Searched all clients, none match expected name"],
        )

    def verify_client_grant(self) -> VerificationResult:
        client = self._find_m2m_client()
        if not client:
            return VerificationResult(
                name="Client Grant",
                passed=False,
                message="Cannot check grant - M2M app not found",
            )

        try:
            resp = self.client.get("client-grants", params={"client_id": client["client_id"]})
            resp.raise_for_status()
            for grant in resp.json():
                if grant.get("audience") == self.audience:
                    grant_scopes = grant.get("scope", [])
                    missing = [s for s in EXPECTED_SCOPES if s not in grant_scopes]

                    if missing:
                        return VerificationResult(
                            name="Client Grant",
                            passed=False,
                            message=f"Grant exists but missing {len(missing)} scope(s)",
                            details=[f"Missing: {', '.join(missing)}"],
                        )

                    return VerificationResult(
                        name="Client Grant",
                        passed=True,
                        message="Client grant exists with all expected scopes",
                        details=[f"Scopes: {', '.join(grant_scopes)}"],
                    )

            return VerificationResult(
                name="Client Grant",
                passed=False,
                message=f"No grant found for audience '{self.audience}'",
            )
        except httpx.HTTPError as e:
            return VerificationResult(
                name="Client Grant",
                passed=False,
                message=f"Error checking client grant: {e}",
            )

    def run_all_checks(self) -> list[VerificationResult]:
        self.results = [
            self.verify_api_exists(),
            self.verify_api_scopes(),
            self.verify_m2m_app_exists(),
            self.verify_client_grant(),
        ]
        return self.results


def print_results(results: list[VerificationResult]) -> bool:
    print("\n" + "=" * 60)
    print("AUTH0 VERIFICATION RESULTS - Rule Engine")
    print("=" * 60 + "\n")

    all_passed = True

    for result in results:
        status = "[PASS]" if result.passed else "[FAIL]"

        print(f"{status} | {result.name}")
        print(f"        {result.message}")
        for detail in result.details:
            print(f"        > {detail}")
        print()

        if not result.passed:
            all_passed = False

    print("=" * 60)
    if all_passed:
        print("[OK] ALL CHECKS PASSED")
    else:
        print("[ERROR] SOME CHECKS FAILED")
        print("\nTo fix issues, re-run the bootstrap:")
        print("  uv run auth0-bootstrap --yes --verbose")
    print("=" * 60)

    print("\nExpected Scopes for Rule Engine:")
    for scope in EXPECTED_SCOPES:
        print(f"  - {scope}")

    print("\nNOTE: Rule Engine uses M2M scope-based auth only.")
    print("No roles, Actions, or trigger bindings are required.")

    return all_passed


def main():
    mgmt_domain = os.getenv("AUTH0_MGMT_DOMAIN")
    mgmt_client_id = os.getenv("AUTH0_MGMT_CLIENT_ID")
    mgmt_client_secret = os.getenv("AUTH0_MGMT_CLIENT_SECRET")
    audience = os.getenv("AUTH0_AUDIENCE")
    m2m_name = os.getenv("AUTH0_M2M_APP_NAME", "Fraud Rule Engine M2M")

    missing = []
    if not mgmt_domain:
        missing.append("AUTH0_MGMT_DOMAIN")
    if not mgmt_client_id:
        missing.append("AUTH0_MGMT_CLIENT_ID")
    if not mgmt_client_secret:
        missing.append("AUTH0_MGMT_CLIENT_SECRET")
    if not audience:
        missing.append("AUTH0_AUDIENCE")

    if missing:
        print(f"ERROR: Missing required environment variables: {', '.join(missing)}")
        print("\nRun with Doppler:")
        print("  doppler run -- python scripts/verify_auth0.py")
        sys.exit(1)

    print(f"Verifying Auth0 configuration...")
    print(f"  Domain: {mgmt_domain}")
    print(f"  Audience: {audience}")
    print(f"  M2M App: {m2m_name}")

    try:
        token_resp = httpx.post(
            f"https://{mgmt_domain}/oauth/token",
            json={
                "client_id": mgmt_client_id,
                "client_secret": mgmt_client_secret,
                "audience": f"https://{mgmt_domain}/api/v2/",
                "grant_type": "client_credentials",
            },
            timeout=30.0,
        )
        token_resp.raise_for_status()
        token = token_resp.json()["access_token"]
    except Exception as e:
        print(f"ERROR: Failed to get management token: {e}")
        sys.exit(1)

    verifier = Auth0Verifier(mgmt_domain, token, audience, m2m_name)
    results = verifier.run_all_checks()

    all_passed = print_results(results)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
