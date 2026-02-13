"""Shared CLI runner helper.

Provides a standard way to run commands inside the uv-managed environment.
"""

import subprocess


def run(cmd):
    """Run a command and propagate its exit code."""
    raise SystemExit(subprocess.run(cmd).returncode)
