#!/usr/bin/env python3
"""
Upload sample ruleset to MinIO.

Usage:
    python scripts/upload_sample_ruleset.py
"""

import os
import sys
from pathlib import Path

import httpx


MINIO_ENDPOINT = os.getenv("S3_ENDPOINT_URL")
MINIO_ACCESS_KEY = os.getenv("S3_ACCESS_KEY_ID")
MINIO_SECRET_KEY = os.getenv("S3_SECRET_ACCESS_KEY")
BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "fraud-gov-artifacts")

if not all([MINIO_ENDPOINT, MINIO_ACCESS_KEY, MINIO_SECRET_KEY]):
    print(
        "ERROR: S3_ENDPOINT_URL, S3_ACCESS_KEY_ID, and S3_SECRET_ACCESS_KEY must be set"
    )
    sys.exit(1)

SAMPLE_RULESET_DIR = Path(__file__).parent.parent / "sample-rulesets"


def get_minio_client():
    return httpx.Client(
        base_url=MINIO_ENDPOINT, auth=(MINIO_ACCESS_KEY, MINIO_SECRET_KEY)
    )


def ensure_bucket_exists(client: httpx.Client) -> bool:
    """Check if bucket exists, create if not."""
    try:
        response = client.head_object(bucket=BUCKET_NAME, key="test")
        print(f"Bucket '{BUCKET_NAME}' exists")
        return True
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            # Try to create bucket
            try:
                response = client.put(bucket=BUCKET_NAME)
                print(f"Created bucket '{BUCKET_NAME}'")
                return True
            except Exception as create_error:
                print(f"Could not create bucket: {create_error}")
                return False
        else:
            print(f"Error checking bucket: {e}")
            return False


def upload_file(client: httpx.Client, local_path: Path, s3_key: str) -> bool:
    """Upload a single file to MinIO."""
    try:
        with open(local_path, "rb") as f:
            content = f.read()

        # Use MinIO/S3 PUT object API
        url = f"{MINIO_ENDPOINT}/{BUCKET_NAME}/{s3_key}"
        headers = {"Content-Type": "application/x-yaml"}

        response = httpx.put(
            url,
            content=content,
            headers=headers,
            auth=(MINIO_ACCESS_KEY, MINIO_SECRET_KEY),
            timeout=30.0,
        )

        if response.status_code in (200, 201):
            print(f"  ✓ Uploaded: {s3_key}")
            return True
        else:
            print(
                f"  ✗ Failed to upload {s3_key}: {response.status_code} - {response.text[:200]}"
            )
            return False

    except Exception as e:
        print(f"  ✗ Error uploading {s3_key}: {e}")
        return False


def upload_sample_rulesets():
    """Upload all sample rulesets to MinIO."""
    client = get_minio_client()

    print(f"Uploading sample rulesets to MinIO...")
    print(f"  Endpoint: {MINIO_ENDPOINT}")
    print(f"  Bucket: {BUCKET_NAME}")
    print()

    # Check if bucket is accessible
    try:
        url = f"{MINIO_ENDPOINT}/{BUCKET_NAME}/test"
        response = httpx.put(
            url,
            content="test",
            auth=(MINIO_ACCESS_KEY, MINIO_SECRET_KEY),
            timeout=5.0,
        )
        # If we get 200/201/404, bucket exists
        print(f"✓ Bucket '{BUCKET_NAME}' is accessible")
    except Exception as e:
        print(f"✗ Cannot access bucket '{BUCKET_NAME}': {e}")
        print("\nTo start MinIO, run from card-fraud-rule-management:")
        print("  cd ../card-fraud-rule-management")
        print("  uv run objstore-local-up")
        return False

    uploaded_count = 0
    skipped_count = 0

    # Walk through sample-rulesets directory
    for ruleset_key in os.listdir(SAMPLE_RULESET_DIR):
        ruleset_path = SAMPLE_RULESET_DIR / ruleset_key
        if not ruleset_path.is_dir():
            continue

        for version_str in os.listdir(ruleset_path):
            version_path = ruleset_path / version_str
            if not version_path.is_dir():
                continue

            ruleset_file = version_path / "ruleset.yaml"
            if not ruleset_file.exists():
                continue

            # Calculate S3 key
            s3_key = f"rulesets/{ruleset_key}/{version_str}/ruleset.yaml"

            # Check if file already exists
            check_url = f"{MINIO_ENDPOINT}/{BUCKET_NAME}/{s3_key}"
            try:
                response = httpx.head(
                    check_url,
                    auth=(MINIO_ACCESS_KEY, MINIO_SECRET_KEY),
                    timeout=5.0,
                )
                print(f"  ⊘ Skipped (exists): {s3_key}")
                skipped_count += 1
                continue
            except Exception:
                pass

            # Upload
            if upload_file(client, ruleset_file, s3_key):
                uploaded_count += 1

    print()
    print(f"Summary:")
    print(f"  Uploaded: {uploaded_count}")
    print(f"  Skipped: {skipped_count}")
    print(f"  Total: {uploaded_count + skipped_count}")

    return True


def main():
    if not SAMPLE_RULESET_DIR.exists():
        print(f"Sample ruleset directory not found: {SAMPLE_RULESET_DIR}")
        sys.exit(1)

    success = upload_sample_rulesets()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
