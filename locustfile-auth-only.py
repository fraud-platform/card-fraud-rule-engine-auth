"""
Locust load testing for Card Fraud Rule Engine - AUTH ONLY

Usage:
  NO_AUTH=true locust -f load-testing/locustfile-auth-only.py --host=http://localhost:8081 \\
    --headless -u 100 -r 10 --run-time=2m
"""

import json
import uuid
import random
import os
from locust import HttpUser, task, constant

# Configuration
NO_AUTH = os.environ.get("NO_AUTH", "false").lower() in ("true", "1", "yes")

# Test data
CARD_HASHES = [
    "4532015112830366",
    "5425233430109903",
    "374245455400126",
    "6011000991001201",
]

CURRENCIES = ["USD", "EUR", "GBP"]
# CRITICAL: Only use US since rulesets are loaded for country="US"
# Other countries will cause FAIL_OPEN: RULESET_NOT_LOADED
COUNTRIES = ["US"]  # Was: ["US", "GB", "CA", "FR", "DE"]
MERCHANT_CATEGORIES = ["5411", "5812", "5999", "7011"]
TRANSACTION_TYPES = ["PURCHASE", "CASH_WITHDRAWAL", "REFUND"]
ENTRY_MODES = ["CHIP", "CONTACTLESS", "MANUAL", "SWIPE"]

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

class AuthOnlyUser(HttpUser):
    """AUTH-only user for focused performance testing."""

    wait_time = constant(0)  # Fire as fast as possible

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.headers = {"Content-Type": "application/json"}

    def on_start(self):
        self.client.verify = False

    @task(1)
    def auth_evaluation(self):
        with self.client.post(
            "/v1/evaluate/auth",
            json=generate_AUTH_request(),
            headers=self.headers,
            catch_response=True,
            name="POST /v1/evaluate/auth",
        ) as response:
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
            elif response.status_code == 401:
                response.failure("Auth failed - use NO_AUTH=true")
            elif response.status_code == 403:
                response.failure("Forbidden - check scopes")
            else:
                response.failure(f"Status {response.status_code}")
