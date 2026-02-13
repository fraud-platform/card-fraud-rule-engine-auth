"""
E2E Tests for AUTH Evaluation Endpoint

Works in both no-auth and JWT modes.
Auth rejection tests are skipped in no-auth mode.
"""

import re
import time

import pytest

from conftest import _is_jwt_mode


class TestAUTHEvaluation:
    """Test AUTH evaluation endpoint."""

    def test_AUTH_approve_low_amount(self, client, test_transaction_id, test_card_hash):
        """Test AUTH with low amount returns a valid response."""
        payload = {
            "transaction_id": test_transaction_id,
            "card_hash": test_card_hash,
            "amount": 50.00,
            "currency": "USD",
            "country_code": "US",
            "merchant_category_code": "5411",
            "transaction_type": "PURCHASE",
        }

        response = client.post("/v1/evaluate/auth", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] in ["APPROVE", "DECLINE"]
        assert data["transaction_id"] == test_transaction_id
        assert data["evaluation_type"] == "AUTH"
        assert "decision_id" in data
        assert "timestamp" in data
        assert data["processing_time_ms"] >= 0

    def test_AUTH_high_amount(self, client, test_card_hash):
        """Test AUTH with high amount returns a valid response."""
        payload = {
            "transaction_id": f"e2e-high-{test_card_hash}",
            "card_hash": test_card_hash,
            "amount": 15000.00,
            "currency": "USD",
            "country_code": "US",
            "merchant_category_code": "5411",
        }

        response = client.post("/v1/evaluate/auth", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] in ["APPROVE", "DECLINE"]
        assert "matched_rules" in data

    def test_AUTH_has_decision_id(self, client, test_transaction_id, test_card_hash):
        """Test that AUTH response includes a valid UUID decision_id."""
        payload = {
            "transaction_id": test_transaction_id,
            "card_hash": test_card_hash,
            "amount": 100.00,
            "currency": "USD",
        }

        response = client.post("/v1/evaluate/auth", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "decision_id" in data
        assert re.match(
            r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$",
            data["decision_id"],
        )

    def test_AUTH_has_timing(self, client, test_transaction_id, test_card_hash):
        """Test that AUTH response includes processing time."""
        payload = {
            "transaction_id": test_transaction_id,
            "card_hash": test_card_hash,
            "amount": 100.00,
            "currency": "USD",
        }

        response = client.post("/v1/evaluate/auth", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "processing_time_ms" in data
        assert data["processing_time_ms"] >= 0

    def test_AUTH_fail_open_no_ruleset(self, client, test_transaction_id, test_card_hash):
        """Test AUTH returns APPROVE (fail-open) when ruleset not found."""
        payload = {
            "transaction_id": test_transaction_id,
            "card_hash": test_card_hash,
            "amount": 100.00,
            "currency": "USD",
            "transaction_type": "UNKNOWN_RULESET_TYPE",
        }

        response = client.post("/v1/evaluate/auth", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert data["decision"] == "APPROVE"
        assert data["engine_mode"] == "FAIL_OPEN"

    @pytest.mark.skipif(not _is_jwt_mode(), reason="Auth rejection only testable in JWT mode")
    def test_AUTH_without_auth_rejected(self, unauth_client, test_transaction_id, test_card_hash):
        """Test AUTH without authentication returns 401/403."""
        payload = {
            "transaction_id": test_transaction_id,
            "card_hash": test_card_hash,
            "amount": 100.00,
            "currency": "USD",
        }

        response = unauth_client.post("/v1/evaluate/auth", json=payload)
        assert response.status_code in [401, 403]


class TestAUTHPerformance:
    """Test AUTH endpoint performance."""

    def test_AUTH_latency_acceptable(self, client, test_card_hash):
        """Test that AUTH latency is within acceptable bounds."""
        payload = {
            "transaction_id": f"e2e-latency-{test_card_hash}",
            "card_hash": test_card_hash,
            "amount": 100.00,
            "currency": "USD",
        }

        start = time.time()
        response = client.post("/v1/evaluate/auth", json=payload)
        elapsed_ms = (time.time() - start) * 1000

        assert response.status_code == 200
        # Local dev mode: < 500ms (includes Quarkus dev overhead)
        assert elapsed_ms < 500, f"Latency {elapsed_ms:.0f}ms exceeds threshold"
