from __future__ import annotations

import argparse
import json
import socket
import sys
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import urlopen

SERVICE_ID = "rule-engine-auth"
HEALTH_URL = "http://localhost:8081/v1/evaluate/health"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _result(
    domain: str,
    action: str,
    status: str,
    summary: str,
    *,
    details: list[str] | None = None,
    started_at: str,
    completed_at: str,
) -> dict[str, object]:
    return {
        "service": SERVICE_ID,
        "domain": domain,
        "action": action,
        "target": "service",
        "status": status,
        "summary": summary,
        "details": details or [],
        "destructive": False,
        "started_at": started_at,
        "completed_at": completed_at,
        "artifacts": [],
        "next_steps": [],
        "error": None,
    }


def _probe_http(url: str) -> tuple[bool, str]:
    try:
        with urlopen(url, timeout=5) as response:
            if 200 <= response.status < 300:
                return True, f"Endpoint reachable at {url}"
            return False, f"Endpoint returned HTTP {response.status}: {url}"
    except URLError as exc:
        return False, f"Endpoint unreachable ({url}): {exc}"


def _probe_port(host: str, port: int, name: str) -> tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=3):
            return True, f"{name} reachable at {host}:{port}"
    except OSError as exc:
        return False, f"{name} unreachable at {host}:{port}: {exc}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Rule engine AUTH platform adapter")
    parser.add_argument("domain")
    parser.add_argument("action")
    parser.add_argument("--format", choices=["json", "text"], default="json")
    args = parser.parse_args()

    started_at = _iso_now()

    if (args.domain, args.action) in {("service", "status"), ("service", "health")}:
        ok, summary = _probe_http(HEALTH_URL)
        completed_at = _iso_now()
        print(
            json.dumps(
                _result(
                    args.domain,
                    args.action,
                    "ok" if ok else "error",
                    summary,
                    started_at=started_at,
                    completed_at=completed_at,
                )
            )
        )
        return 0 if ok else 1

    if (args.domain, args.action) == ("service", "logs"):
        completed_at = _iso_now()
        print(
            json.dumps(
                _result(
                    args.domain,
                    args.action,
                    "ok",
                    "Use docker compose logs for rule-engine-auth logs",
                    details=[
                        "docker compose -f docker-compose.yml -f docker-compose.apps.yml logs rule-engine-auth"
                    ],
                    started_at=started_at,
                    completed_at=completed_at,
                )
            )
        )
        return 0

    if (args.domain, args.action) == ("runtime", "verify"):
        checks = [
            _probe_http(HEALTH_URL),
            _probe_port("localhost", 6379, "Redis"),
        ]
    elif (args.domain, args.action) == ("messaging", "verify"):
        checks = [_probe_port("localhost", 9092, "Kafka/Redpanda")]
    elif (args.domain, args.action) == ("storage", "verify"):
        checks = [_probe_port("localhost", 9000, "MinIO")]
    else:
        completed_at = _iso_now()
        print(
            json.dumps(
                _result(
                    args.domain,
                    args.action,
                    "error",
                    f"Unsupported action: {args.domain}:{args.action}",
                    started_at=started_at,
                    completed_at=completed_at,
                )
            )
        )
        return 2

    ok = all(check[0] for check in checks)
    summary = "All dependency checks passed" if ok else "One or more dependency checks failed"
    details = [message for _, message in checks]
    completed_at = _iso_now()
    print(
        json.dumps(
            _result(
                args.domain,
                args.action,
                "ok" if ok else "error",
                summary,
                details=details,
                started_at=started_at,
                completed_at=completed_at,
            )
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
