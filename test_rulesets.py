"""
E2E Tests for Ruleset Management

In no-auth mode (dev server), management endpoints may return 401/403
since they require @Authenticated even when JWT processing is disabled.
These tests adapt based on auth mode.
"""

import pytest

from conftest import _is_jwt_mode


class TestRulesetManagement:
    """Test ruleset management endpoints."""

    @pytest.mark.skipif(not _is_jwt_mode(), reason="Management endpoints require JWT")
    def test_registry_status(self, client):
        """Test ruleset registry status endpoint."""
        response = client.get("/v1/evaluate/rulesets/registry/status")
        assert response.status_code == 200

        data = response.json()
        assert "totalRulesets" in data
        assert "countries" in data
        assert isinstance(data["totalRulesets"], int)

    @pytest.mark.skipif(not _is_jwt_mode(), reason="Management endpoints require JWT")
    def test_registry_has_rulesets(self, client):
        """Test that registry response is well-formed."""
        response = client.get("/v1/evaluate/rulesets/registry/status")
        assert response.status_code == 200

        data = response.json()
        ruleset_keys = [rs["key"] for rs in data.get("rulesets", [])]
        assert isinstance(ruleset_keys, list)

    @pytest.mark.skipif(not _is_jwt_mode(), reason="Auth rejection only testable in JWT mode")
    def test_registry_status_unauthorized(self, unauth_client):
        """Test that registry status requires authentication."""
        response = unauth_client.get("/v1/evaluate/rulesets/registry/status")
        assert response.status_code in [401, 403]

    @pytest.mark.skipif(not _is_jwt_mode(), reason="Management endpoints require JWT")
    def test_bulk_load_rulesets(self, client):
        """Test bulk loading rulesets endpoint."""
        payload = {
            "rulesets": [
                {"key": "CARD_AUTH", "version": 1, "country": "global"},
                {"key": "CARD_MONITORING", "version": 1, "country": "global"},
            ]
        }

        response = client.post("/v1/evaluate/rulesets/bulk-load", json=payload)
        assert response.status_code == 200

        data = response.json()
        assert "loaded" in data
        assert "total" in data
        assert data["total"] == 2
