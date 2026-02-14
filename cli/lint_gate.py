"""Lint gate wrapper for local quality checks."""

from __future__ import annotations

import os
import subprocess
import sys


def _run(cmd: list[str], label: str) -> None:
    print(f"[lint] {label}: {' '.join(cmd)}")
    result = subprocess.run(cmd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> None:
    """Run Python and Java lint/quality checks."""
    # Lint CLI helpers and local scripts.
    _run([sys.executable, "-m", "ruff", "check", "cli"], "python")
    # Java compile gate catches syntax/import issues quickly without running tests.
    mvn = "mvn.cmd" if os.name == "nt" else "mvn"
    _run([mvn, "-B", "-DskipTests", "compile"], "java")
