"""
Locust load testing for Card Fraud Rule Engine.

Gateway auth model:
  - Token verification is handled upstream by API Gateway.
  - Rule engine load tests call the service directly without Authorization headers.

Usage:
  # Start server (terminal 1)
  uv run doppler-load-test

  # Run Locust (terminal 2)
  doppler run --project card-fraud-rule-engine --config=local -- \\
    locust -f load-testing/locustfile.py --host=http://localhost:8081

  # Headless mode
  locust -f load-testing/locustfile.py --host=http://localhost:8081 \\
    --headless -u 50 -r 5 --run-time=2m

  # Docker Compose (all-in-one)
  doppler run --project card-fraud-rule-engine --config=local -- \\
    docker compose --profile load-testing up

Targets:
  - P95 latency < 15ms for AUTH
  - P99 latency < 30ms
  - 10,000+ TPS sustained
"""

import json
import uuid
import random
import os
from locust import HttpUser, task, between, constant, events
import urllib.request

# ========== Configuration ==========

TARGET_HOST = os.environ.get("TARGET_HOST", "http://localhost:8081")

# Test data pools
CURRENCIES = ["USD", "GBP", "EUR", "CAD", "AUD", "JPY"]
COUNTRIES = ["US", "GB", "CA", "DE", "FR", "AU", "JP", "IN", "BR", "MX"]
MERCHANT_CATEGORIES = ["5411", "5999", "5734", "5812", "5541", "5942", "5912"]
TRANSACTION_TYPES = ["PURCHASE", "AUTHORIZATION"]
ENTRY_MODES = ["ECOM", "CHIP", "MAGSTRIPE", "CONTACTLESS", "MANUAL"]
CARD_HASHES = [f"card_hash_{i:04d}" for i in range(100)]


# ========== Request Generators ==========

def generate_transaction_id():
    return f"txn-{uuid.uuid4().hex[:16]}"


def generate_card_bin():
    visa_bins = ["411111", "400000", "450000"]
    mc_bins = ["555555", "520000", "540000"]
    amex_bins = ["340000", "370000"]
    return random.choice(visa_bins + mc_bins + amex_bins)


def generate_AUTH_request():
    card_bin = generate_card_bin()
    network = (
        "VISA" if card_bin.startswith("4")
        else ("MASTERCARD" if card_bin.startswith("5") else "AMEX")
    )
    return {
        "transaction_id": generate_transaction_id(),
        "card_hash": random.choice(CARD_HASHES),
        "amount": round(random.uniform(10.0, 2000.0), 2),
        "currency": random.choice(CURRENCIES),
        "country_code": random.choice(COUNTRIES),
        "merchant_id": f"merch_{random.randint(1000, 9999)}",
        "merchant_name": f"Test Merchant {random.randint(1, 100)}",
        "merchant_category": random.choice(MERCHANT_CATEGORIES),
        "merchant_category_code": random.choice(MERCHANT_CATEGORIES),
        "card_present": random.choice([True, False]),
        "transaction_type": random.choice(TRANSACTION_TYPES),
        "entry_mode": random.choice(ENTRY_MODES),
        "ip_address": f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}",
        "device_id": f"device_{random.randint(1000, 9999)}",
        "card_network": network,
        "card_bin": card_bin,
    }


def generate_MONITORING_request():
    return {
        "transaction_id": generate_transaction_id(),
        "card_hash": random.choice(CARD_HASHES),
        "amount": round(random.uniform(10.0, 500.0), 2),
        "currency": random.choice(CURRENCIES),
        "country_code": random.choice(COUNTRIES),
        "merchant_id": f"merch_{random.randint(1000, 9999)}",
        "merchant_category_code": random.choice(MERCHANT_CATEGORIES),
        "decision": random.choice(["APPROVE", "DECLINE"]),
    }


def generate_velocity_burst_request():
    req = generate_AUTH_request()
    req["card_hash"] = "velocity_test_card"
    req["amount"] = round(random.uniform(50.0, 200.0), 2)
    return req


# ========== Locust User Classes ==========

class CardFraudUser(HttpUser):
    """Standard user: 70% AUTH, 30% MONITORING."""

    wait_time = constant(0)  # Fire as fast as possible for throughput testing

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = self._get_headers()

    def on_start(self):
        self.client.verify = False

    def _get_headers(self):
        return {"Content-Type": "application/json"}

    @task(7)
    def AUTH_evaluation(self):
        with self.client.post(
            "/v1/evaluate/auth",
            json=generate_AUTH_request(),
            headers=self.headers,
            catch_response=True,
            name="/v1/evaluate/auth",
        ) as response:
            self._handle_response(response, "AUTH")

    @task(3)
    def MONITORING_evaluation(self):
        with self.client.post(
            "/v1/evaluate/monitoring",
            json=generate_MONITORING_request(),
            headers=self.headers,
            catch_response=True,
            name="/v1/evaluate/monitoring",
        ) as response:
            self._handle_response(response, "MONITORING")

    def _handle_response(self, response, eval_type):
        if response.status_code == 200:
            try:
                data = response.json()
                mode = data.get("engine_mode", "NORMAL")
                if mode in ("FAIL_OPEN", "DEGRADED"):
                    error_code = data.get("engine_error_code", "UNKNOWN")
                    response.failure(f"{mode}: {error_code}")
                else:
                    response.success()
            except json.JSONDecodeError:
                response.failure("Invalid JSON response")
        else:
            response.failure(f"Status {response.status_code}: {response.text[:100]}")


class HighVolumeUser(CardFraudUser):
    """High-volume stress testing user."""
    wait_time = constant(0)  # Fire as fast as possible


class VelocityTestUser(CardFraudUser):
    """Velocity limit testing user."""
    wait_time = between(0.1, 0.2)  # 100-200ms between requests

    @task
    def velocity_burst(self):
        with self.client.post(
            "/v1/evaluate/auth",
            json=generate_velocity_burst_request(),
            headers=self.headers,
            catch_response=True,
            name="/v1/evaluate/auth [velocity]",
        ) as response:
            self._handle_response(response, "VELOCITY")


class SteadyStateUser(HttpUser):
    """Steady-state baseline measurement user."""
    wait_time = constant(0.1)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = self._get_headers()

    def _get_headers(self):
        return {"Content-Type": "application/json"}

    @task
    def AUTH_only(self):
        self.client.post(
            "/v1/evaluate/auth",
            json=generate_AUTH_request(),
            headers=self.headers,
        )


# ========== Event Handlers ==========

@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("=" * 60)
    print("Card Fraud Rule Engine Load Test")
    print(f"  Target: {environment.host}")
    print("=" * 60)

    # Load rulesets before starting
    try:
        headers = {"Content-Type": "application/json"}

        bulk_load_payload = {
            "rulesets": [
                {"key": "CARD_AUTH", "version": 1, "country": "global"},
                {"key": "CARD_MONITORING", "version": 1, "country": "global"},
            ]
        }

        host = environment.host or TARGET_HOST
        url = f"{host}/v1/evaluate/rulesets/bulk-load"
        data = json.dumps(bulk_load_payload).encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode())
            print(f"  Rulesets loaded: {result.get('loaded', 0)} / {result.get('total', 0)}")
    except Exception as e:
        print(f"  Warning: Could not load rulesets: {e}")
        print("  Load test will proceed with existing rulesets (if any)")

    print("=" * 60)


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    print("=" * 60)
    print("Load Test Complete")
    print("=" * 60)


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, context, **kwargs):
    # Sample 0.1% of slow requests to avoid flooding console at high TPS
    if response_time > 100 and random.random() < 0.001:
        print(f"SLOW: {name} {response_time:.0f}ms")
