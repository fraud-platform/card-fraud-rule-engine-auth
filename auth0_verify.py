"""CLI wrapper for Auth0 verification with Doppler."""

import sys

from cli._doppler import doppler_run_prefix
from cli._runner import run


def main():
    """Run Auth0 verification with Doppler secrets."""
    cmd = doppler_run_prefix("local") + [sys.executable, "scripts/verify_auth0.py"]
    run(cmd)


if __name__ == "__main__":
    main()
