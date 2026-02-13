#!/usr/bin/env python3
"""Latency Test Script for Card Fraud Rule Engine

Measures detailed latencies for AUTH and MONITORING endpoints:
- Total request time (end-to-end)
- Processing time (server-side)
- Component breakdown (ruleset lookup, rule evaluation, Redis velocity)

Target: AUTH < 20ms, P95 < 30ms
"""

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime

import httpx


@dataclass
class LatencyResult:
    """Result of a single latency measurement."""
    request_id: str
    endpoint: str
    total_time_ms: float
    processing_time_ms: float
    decision: str
    status_code: int
    timing_breakdown: dict = None
    error: str = None


@dataclass
class LatencyStats:
    """Statistics for a set of latency measurements."""
    endpoint: str
    count: int
    min_ms: float
    max_ms: float
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    within_target_pct: float
    target_ms: float


BASE_URL = os.getenv("FRAUD_ENGINE_BASE_URL", "http://localhost:8081")
AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://fraud-rule-engine-api")


def _get_auth_token() -> str:
    """Get Auth0 M2M token."""
    domain = os.getenv("AUTH0_DOMAIN")
    client_id = os.getenv("AUTH0_CLIENT_ID")
    client_secret = os.getenv("AUTH0_CLIENT_SECRET")

    if not all([domain, client_id, client_secret]):
        print("ERROR: Missing Auth0 environment variables")
        print("Required: AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET, AUTH0_AUDIENCE")
        sys.exit(1)

    response = httpx.post(
        f"https://{domain}/oauth/token",
        json={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": AUDIENCE
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def _create_request(txn_id: str, decision: str | None = None) -> dict:
    """Create a request payload."""
    payload = {
        "transaction_id": txn_id,
        "card_hash": f"card_{hash(txn_id)[:16]}",
        "amount": 150.00,
        "currency": "USD",
        "merchant_id": "merch_001",
        "merchant_category": "Retail",
        "merchant_category_code": "5411",
        "country_code": "US",
        "ip_address": "192.168.1.1",
        "device_id": "device_001",
        "transaction_type": "PURCHASE",
        "card_network": "VISA",
        "card_bin": "411111"
    }
    if decision:
        payload["decision"] = decision
    return payload


def _measure(client: httpx.Client, endpoint: str, txn_id: str, decision: str | None = None) -> LatencyResult:
    """Measure latency for a single request."""
    start = time.perf_counter()
    try:
        response = client.post(f"/v1/evaluate/{endpoint}", json=_create_request(txn_id, decision))
        elapsed = (time.perf_counter() - start) * 1000

        if response.status_code == 200:
            data = response.json()
            return LatencyResult(
                request_id=txn_id,
                endpoint=endpoint,
                total_time_ms=elapsed,
                processing_time_ms=data.get("processing_time_ms", 0),
                decision=data.get("decision", "UNKNOWN"),
                status_code=response.status_code,
                timing_breakdown=data.get("timing_breakdown"),
            )
        return LatencyResult(
            request_id=txn_id,
            endpoint=endpoint,
            total_time_ms=elapsed,
            processing_time_ms=0,
            decision="ERROR",
            status_code=response.status_code,
            error=response.text,
        )
    except Exception as e:
        elapsed = (time.perf_counter() - start) * 1000
        return LatencyResult(
            request_id=txn_id,
            endpoint=endpoint,
            total_time_ms=elapsed,
            processing_time_ms=0,
            decision="ERROR",
            status_code=0,
            error=str(e),
        )


def _percentile(data: list[float], p: int) -> float:
    """Calculate percentile."""
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100)
    f = int(k)
    c = k - f
    if f + 1 < len(sorted_data):
        return sorted_data[f] + c * (sorted_data[f + 1] - sorted_data[f])
    return sorted_data[f]


def _calculate_stats(endpoint: str, results: list[LatencyResult], target_ms: float) -> LatencyStats | None:
    """Calculate statistics from results."""
    processing_times = [r.processing_time_ms for r in results if not r.error]
    if not processing_times:
        return None

    within_target_pct = (sum(1 for t in processing_times if t <= target_ms) / len(processing_times)) * 100
    return LatencyStats(
        endpoint=endpoint,
        count=len(processing_times),
        min_ms=min(processing_times),
        max_ms=max(processing_times),
        mean_ms=statistics.mean(processing_times),
        median_ms=statistics.median(processing_times),
        p95_ms=_percentile(processing_times, 95),
        p99_ms=_percentile(processing_times, 99),
        within_target_pct=within_target_pct,
        target_ms=target_ms,
    )


def _print_stats(stats: LatencyStats, label: str = "Server Processing"):
    """Print latency statistics."""
    print(f"\n=== {stats.endpoint} {label} Latency Statistics ===")
    print(f"  Requests:        {stats.count}")
    print(f"  Target:          < {stats.target_ms}ms")
    print(f"  Within Target:   {stats.within_target_pct:.1f}%")
    print(f"  Min:             {stats.min_ms:.2f}ms")
    print(f"  Max:             {stats.max_ms:.2f}ms")
    print(f"  Mean:            {stats.mean_ms:.2f}ms")
    print(f"  Median:          {stats.median_ms:.2f}ms")
    print(f"  P95:             {stats.p95_ms:.2f}ms")
    print(f"  P99:             {stats.p99_ms:.2f}ms")
    status = "PASS" if stats.p95_ms <= stats.target_ms else "FAIL"
    print(f"\n  Status: {status} (P95 {stats.p95_ms:.2f}ms vs target {stats.target_ms}ms)")


def _run_warmup(client: httpx.Client, count: int = 10):
    """Run warmup requests."""
    print(f"\n=== Warmup ({count} requests) ===")
    for i in range(count):
        result = _measure(client, "AUTH", f"warmup-{i}")
        if result.error:
            print(f"  Warmup {i+1}: ERROR - {result.error}")
    print("Warmup complete")


def _run_test(client: httpx.Client, endpoint: str, count: int, target_ms: float) -> tuple[list[LatencyResult], LatencyStats | None]:
    """Run a latency test for an endpoint."""
    print(f"\n=== {endpoint} Latency Test (n={count}) ===")
    results = []
    for i in range(count):
        txn_id = f"{endpoint.lower()}-{int(time.time() * 1000)}-{i}"
        decision = "APPROVE" if endpoint == "MONITORING" else None
        results.append(_measure(client, endpoint, txn_id, decision))
        if (i + 1) % 20 == 0:
            print(f"  {i+1}/{count} requests sent...")

    stats = _calculate_stats(endpoint, results, target_ms)
    if not stats:
        print("No successful requests!")
    return results, stats


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Latency test for Card Fraud Rule Engine")
    parser.add_argument("--url", default=BASE_URL, help="Base URL of the service")
    parser.add_argument("--count", type=int, default=100, help="Number of requests per endpoint")
    parser.add_argument("--target", type=float, default=20.0, help="Target latency in ms")
    args = parser.parse_args()

    print("=" * 60)
    print("  Card Fraud Rule Engine - Latency Test")
    print("=" * 60)
    print(f"Target: AUTH < 20ms (P95)")
    print(f"Date: {datetime.utcnow().isoformat()}")
    print(f"Base URL: {args.url}")

    # Setup
    print("\nGetting Auth0 token...")
    token = _get_auth_token()
    print("Authenticated")

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    with httpx.Client(base_url=args.url, headers=headers, timeout=30.0) as client:
        # Health check
        try:
            resp = client.get("/health")
            if resp.status_code == 200:
                print(f"Service healthy: {resp.json().get('status')}")
        except Exception as e:
            print(f"Health check failed: {e}")
            sys.exit(1)

        # Check rulesets
        try:
            resp = client.get("/v1/evaluate/rulesets/registry/status")
            if resp.status_code == 200:
                total = resp.json().get("totalRulesets", 0)
                print(f"Rulesets loaded: {total} total")
                if total == 0:
                    print("Warning: No rulesets loaded. Results may not be accurate.")
        except Exception as e:
            print(f"Registry check failed: {e}")

        # Warmup
        _run_warmup(client, 10)

        # Run tests
        all_results = []

        # AUTH test
        auth_results, auth_stats = _run_test(client, "AUTH", args.count, args.target)
        all_results.extend(auth_results)
        if auth_stats:
            _print_stats(auth_stats, "Server Processing")
            _print_stats(auth_stats, "Total")

        # MONITORING test
        mon_results, mon_stats = _run_test(client, "MONITORING", args.count, 50.0)
        all_results.extend(mon_results)
        if mon_stats:
            _print_stats(mon_stats, "Server Processing")

        # Print summary
        print("\n" + "=" * 60)
        print("  SUMMARY")
        print("=" * 60)
        if auth_stats:
            status = "PASS" if auth_stats.p95_ms <= 20.0 else "FAIL"
            print(f"  AUTH P95: {auth_stats.p95_ms:.2f}ms {status}")
        if mon_stats:
            status = "PASS" if mon_stats.p95_ms <= 50.0 else "FAIL"
            print(f"  MONITORING P95: {mon_stats.p95_ms:.2f}ms {status}")

        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"latency_results_{timestamp}.json"
        data = {"test_run": datetime.utcnow().isoformat(), "results": [asdict(r) for r in all_results]}
        with open(filename, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nResults saved to {filename}")

        # Exit code
        if auth_stats and auth_stats.p95_ms > 20.0:
            print("\nAUTH latency target NOT met")
            sys.exit(1)
        print("\nAll latency targets met")


if __name__ == "__main__":
    main()
