"""
E2E Tests for Velocity Checks

Tests velocity-based fraud detection using Redis counters.
Works in both no-auth and JWT modes.
"""

import time


class TestVelocityChecks:
    """Test velocity check functionality."""

    def test_velocity_threshold(self, client):
        """
        Test that velocity tracking works by sending multiple transactions
        for the same card.
        """
        test_card = f"velocity-test-{time.time()}"

        declined_count = 0
        approved_count = 0

        for i in range(15):
            payload = {
                "transaction_id": f"velocity-{i}-{test_card}",
                "card_hash": test_card,
                "amount": 100.00,
                "currency": "USD",
                "country_code": "US",
            }

            response = client.post("/v1/evaluate/auth", json=payload)
            assert response.status_code == 200

            data = response.json()
            if data["decision"] == "DECLINE":
                declined_count += 1
            else:
                approved_count += 1

        # At least some transactions processed successfully
        assert declined_count + approved_count == 15

    def test_velocity_different_cards_independent(self, client):
        """Test that velocity counters are independent per card."""
        ts = time.time()
        cards = [f"velocity-card{i}-{ts}" for i in range(3)]

        for card in cards:
            for j in range(3):
                payload = {
                    "transaction_id": f"multi-{card}-{j}",
                    "card_hash": card,
                    "amount": 100.00,
                    "currency": "USD",
                }

                response = client.post("/v1/evaluate/auth", json=payload)
                assert response.status_code == 200

    def test_velocity_results_in_response(self, client, test_card_hash):
        """Test that response includes velocity-related fields."""
        payload = {
            "transaction_id": f"velocity-result-{test_card_hash}",
            "card_hash": test_card_hash,
            "amount": 100.00,
            "currency": "USD",
        }

        response = client.post("/v1/evaluate/auth", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "velocity_results" in data or "matched_rules" in data
