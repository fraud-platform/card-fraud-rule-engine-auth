#!/usr/bin/env python3
"""
Load CARD_AUTH ruleset to the rule engine.

This script:
1. Fetches an Auth0 M2M token
2. Uploads the ruleset to MinIO if not present
3. Calls the bulk-load endpoint to load the ruleset

Usage:
    python scripts/load_AUTH_ruleset.py

Required env vars:
    AUTH0_DOMAIN - Auth0 domain (e.g., dev-xyz.us.auth0.com)
    AUTH0_CLIENT_ID - Auth0 M2M client ID
    AUTH0_CLIENT_SECRET - Auth0 M2M client secret
    AUTH0_AUDIENCE - Auth0 API audience (e.g., https://fraud-rule-engine-api)
    S3_ENDPOINT_URL - MinIO endpoint (e.g., http://localhost:9000)
    S3_ACCESS_KEY_ID - MinIO access key
    S3_SECRET_ACCESS_KEY - MinIO secret key
    S3_BUCKET_NAME - MinIO bucket (default: fraud-gov-artifacts)
"""

import json
import os
import sys
from pathlib import Path

import httpx


# Configuration
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE")

MINIO_ENDPOINT = os.getenv("S3_ENDPOINT_URL")
MINIO_ACCESS_KEY = os.getenv("S3_ACCESS_KEY_ID")
MINIO_SECRET_KEY = os.getenv("S3_SECRET_ACCESS_KEY")
MINIO_BUCKET = os.getenv("S3_BUCKET_NAME", "fraud-gov-artifacts")

RULESET_FILE = Path(__file__).parent / "e2e" / "CARD_AUTH-ruleset.json"
BULK_LOAD_URL = "http://localhost:8081/v1/evaluate/rulesets/bulk-load"


def check_required_env_vars():
    """Verify all required environment variables are set."""
    required = {
        "AUTH0_DOMAIN": AUTH0_DOMAIN,
        "AUTH0_CLIENT_ID": AUTH0_CLIENT_ID,
        "AUTH0_CLIENT_SECRET": AUTH0_CLIENT_SECRET,
        "AUTH0_AUDIENCE": AUTH0_AUDIENCE,
        "S3_ENDPOINT_URL": MINIO_ENDPOINT,
        "S3_ACCESS_KEY_ID": MINIO_ACCESS_KEY,
        "S3_SECRET_ACCESS_KEY": MINIO_SECRET_KEY,
    }

    missing = [name for name, value in required.items() if not value]
    if missing:
        print(f"ERROR: Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)


def get_auth0_token() -> str:
    """Fetch Auth0 M2M token using client credentials flow."""
    url = f"https://{AUTH0_DOMAIN}/oauth/token"

    payload = {
        "grant_type": "client_credentials",
        "client_id": AUTH0_CLIENT_ID,
        "client_secret": AUTH0_CLIENT_SECRET,
        "audience": AUTH0_AUDIENCE,
    }

    try:
        response = httpx.post(url, json=payload, timeout=30.0)
        response.raise_for_status()
        token_data = response.json()
        return token_data["access_token"]
    except httpx.HTTPError as e:
        print(f"ERROR: Failed to get Auth0 token: {e}")
        sys.exit(1)


def load_ruleset_data() -> dict:
    """Load the ruleset from the JSON file."""
    if not RULESET_FILE.exists():
        print(f"ERROR: Ruleset file not found: {RULESET_FILE}")
        sys.exit(1)

    try:
        with open(RULESET_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"ERROR: Failed to parse ruleset JSON: {e}")
        sys.exit(1)


def check_ruleset_in_minio(ruleset_key: str, version: int) -> bool:
    """Check if the ruleset already exists in MinIO."""
    # The ruleset is stored as ruleset.json in MinIO
    s3_key = f"rulesets/{ruleset_key}/{version}/ruleset.json"
    url = f"{MINIO_ENDPOINT}/{MINIO_BUCKET}/{s3_key}"

    try:
        response = httpx.head(
            url,
            auth=(MINIO_ACCESS_KEY, MINIO_SECRET_KEY),
            timeout=5.0,
        )
        return response.status_code == 200
    except httpx.HTTPError:
        return False


def upload_ruleset_to_minio(ruleset_data: dict, ruleset_key: str, version: int) -> bool:
    """Upload the ruleset to MinIO."""
    s3_key = f"rulesets/{ruleset_key}/{version}/ruleset.json"
    url = f"{MINIO_ENDPOINT}/{MINIO_BUCKET}/{s3_key}"

    try:
        content = json.dumps(ruleset_data).encode("utf-8")
        headers = {"Content-Type": "application/json"}

        response = httpx.put(
            url,
            content=content,
            headers=headers,
            auth=(MINIO_ACCESS_KEY, MINIO_SECRET_KEY),
            timeout=30.0,
        )

        if response.status_code in (200, 201):
            print(f"  [OK] Uploaded ruleset to MinIO: {s3_key}")
            return True
        else:
            print(
                f"  [FAIL] Failed to upload ruleset: {response.status_code} - {response.text[:200]}"
            )
            return False
    except httpx.HTTPError as e:
        print(f"  [FAIL] Error uploading ruleset to MinIO: {e}")
        return False


def call_bulk_load_endpoint(token: str, ruleset_key: str, version: int) -> bool:
    """Call the bulk-load endpoint to load the ruleset."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    payload = {
        "rulesets": [{"key": ruleset_key, "version": version, "country": "global"}]
    }

    try:
        response = httpx.post(
            BULK_LOAD_URL,
            headers=headers,
            json=payload,
            timeout=30.0,
        )

        if response.status_code == 200:
            result = response.json()
            print(f"  [OK] Bulk load successful: {result}")
            return True
        else:
            print(
                f"  [FAIL] Bulk load failed: {response.status_code} - {response.text[:500]}"
            )
            return False
    except httpx.HTTPError as e:
        print(f"  [FAIL] Error calling bulk-load endpoint: {e}")
        return False


def main():
    print("Loading CARD_AUTH ruleset...")
    print()

    # Check environment variables
    check_required_env_vars()

    # Load ruleset data
    ruleset_data = load_ruleset_data()
    ruleset_key = ruleset_data.get("ruleset_key", "CARD_AUTH")
    ruleset_version = ruleset_data.get("ruleset_version", 1)

    print(f"Ruleset: {ruleset_key} v{ruleset_version}")
    print(f"  File: {RULESET_FILE}")
    print(f"  Rules: {len(ruleset_data.get('rules', []))}")
    print()

    # Step 1: Get Auth0 token
    print("Step 1: Fetching Auth0 M2M token...")
    token = get_auth0_token()
    print("  [OK] Token obtained successfully")
    print()

    # Step 2: Check and upload to MinIO if needed
    print("Step 2: Checking MinIO storage...")
    if check_ruleset_in_minio(ruleset_key, ruleset_version):
        print(f"  [SKIP] Ruleset already exists in MinIO (skipping upload)")
    else:
        print(f"  [INFO] Ruleset not found in MinIO, uploading...")
        if not upload_ruleset_to_minio(ruleset_data, ruleset_key, ruleset_version):
            print("ERROR: Failed to upload ruleset to MinIO")
            sys.exit(1)
    print()

    # Step 3: Call bulk-load endpoint
    print("Step 3: Calling bulk-load endpoint...")
    success = call_bulk_load_endpoint(token, ruleset_key, ruleset_version)

    if success:
        print()
        print("[SUCCESS] Ruleset loaded successfully!")
        print(f"  Key: {ruleset_key}")
        print(f"  Version: {ruleset_version}")
        sys.exit(0)
    else:
        print()
        print("[FAIL] Failed to load ruleset")
        sys.exit(1)


if __name__ == "__main__":
    main()
