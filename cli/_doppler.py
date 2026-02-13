"""Doppler utilities for CLI scripts."""

_DOPPLER_PROJECT = "card-fraud-rule-engine"


def doppler_run_prefix(config: str) -> list[str]:
    """Return the doppler run command prefix for a given config."""
    return [
        "doppler",
        "run",
        "--project",
        _DOPPLER_PROJECT,
        f"--config={config}",
        "--",
    ]
