"""
Doppler development commands for Java/Quarkus.

Run development commands with Doppler secrets injected.

Usage:
    uv run doppler-local        # Run dev server with Doppler (local config)
    uv run doppler-local-test   # Run tests with Doppler (local config - local Redis)
    uv run doppler-test         # Run tests with Doppler (test config)
    uv run doppler-prod         # Run tests with Doppler (prod config)
"""

"""Doppler development commands for Java/Quarkus.

Run development commands with Doppler secrets injected.

Usage:
    uv run doppler-local        # Run dev server with Doppler (local config)
    uv run doppler-local-test   # Run tests with Doppler (local config - local Redis)
    uv run doppler-test         # Run tests with Doppler (test config)
    uv run doppler-prod         # Run tests with Doppler (prod config)
"""

import os

from cli._runner import run
from cli._doppler import doppler_run_prefix


def main():
    """Run Quarkus dev server with Doppler secrets (local config)."""
    os.environ.setdefault("QUARKUS_ENV", "local")
    run(doppler_run_prefix("local") + ["mvn", "quarkus:dev"])


def test_local():
    """Run tests with Doppler secrets (local config - for local Redis testing)."""
    run(doppler_run_prefix("local") + ["mvn", "test"])


def test():
    """Run tests with Doppler secrets (test config)."""
    run(doppler_run_prefix("test") + ["mvn", "verify"])


def test_prod():
    """Run tests with Doppler secrets (prod config)."""
    run(doppler_run_prefix("prod") + ["mvn", "verify"])


def verify_secrets():
    """Verify Doppler secrets are accessible for local config."""
    from cli._doppler import _DOPPLER_PROJECT
    run(["doppler", "secrets", "--project", _DOPPLER_PROJECT, "--config=local", "--only-names"])
