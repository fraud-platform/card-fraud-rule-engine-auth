"""Security gate command for dependency vulnerability checks."""

from __future__ import annotations

import subprocess


def test() -> None:
    """Run Snyk dependency scan and propagate exit status."""
    result = subprocess.run(["snyk", "test"])
    raise SystemExit(result.returncode)
