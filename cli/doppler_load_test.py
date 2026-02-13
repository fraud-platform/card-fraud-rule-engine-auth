"""Doppler load testing commands for Java/Quarkus.

Run load testing commands with Doppler secrets injected.

Usage:
    uv run doppler-load-test    # Run load test server with Doppler (local config)
"""

import os

from cli._runner import run
from cli._doppler import doppler_run_prefix


def main():
    """Run Quarkus load-test server with Doppler secrets (local config)."""
    os.environ.setdefault("QUARKUS_ENV", "local")
    os.environ.setdefault("QUARKUS_PROFILE", "load-test")
    run(doppler_run_prefix("local") + ["mvn", "quarkus:dev", "-Dquarkus.profile=load-test"])