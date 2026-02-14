"""Auth0 bootstrap wrapper (Doppler + uv-friendly).

Provides a single command for onboarding (humans and agents):

    uv run auth0-bootstrap --yes --verbose

By default, runs under Doppler `local` config to inject secrets.

This wrapper intentionally:
- Restricts passthrough args (only --yes/-y and --verbose)
- Avoids printing secrets
- Is safe to re-run because scripts/setup_auth0.py is idempotent
"""

import argparse
import os
import sys
from pathlib import Path

from cli._doppler import doppler_run_prefix
from cli._runner import run


_DOPPLER_PROJECT = "card-fraud-rule-engine"
_SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
_SETUP_AUTH0_SCRIPT = _SCRIPTS_DIR / "setup_auth0.py"


def _validate_doppler_config(value: str) -> str:
    config = value.strip().lower()
    allowed = {"local", "test", "prod"}
    if config not in allowed:
        raise SystemExit(f"Unsupported --config '{value}'. Allowed: {', '.join(sorted(allowed))}")
    return config


def main():
    parser = argparse.ArgumentParser(
        description="Bootstrap Auth0 tenant objects (idempotent). Defaults to Doppler 'local' config."
    )
    parser.add_argument("--config", default="local", help="Doppler config to use (default: local).")
    parser.add_argument("--no-doppler", action="store_true", help="Run without Doppler (expects env vars already set).")
    parser.add_argument("--yes", "-y", action="store_true", help="Run without prompting")
    parser.add_argument("--verbose", action="store_true", help="Print created/updated object IDs")
    args, unknown = parser.parse_known_args()

    if unknown:
        raise SystemExit(
            f"Unsupported extra arguments: {' '.join(unknown)}\n"
            "Only --yes/-y and --verbose are forwarded to the underlying script."
        )

    script_args = []
    if args.yes:
        script_args.append("--yes")
    if args.verbose:
        script_args.append("--verbose")

    cmd = [sys.executable, str(_SETUP_AUTH0_SCRIPT), *script_args]

    if args.no_doppler:
        run(cmd)

    os.environ["ENV_FILE"] = ""  # Ensure dotenv files don't override Doppler secrets
    run(doppler_run_prefix(_validate_doppler_config(args.config)) + cmd)
