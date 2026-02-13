"""
E2E Tests for Health Endpoints

Health endpoints do NOT require authentication in any mode.
"""

import pytest


class TestHealthEndpoints:
    """Test health check endpoints (no auth required)."""

    def test_health_up(self, unauth_client):
        """Test that the custom health endpoint returns UP status."""
        response = unauth_client.get("/v1/evaluate/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "UP"

    def test_health_has_storage_accessible(self, unauth_client):
        """Test that the health endpoint includes storage status."""
        response = unauth_client.get("/v1/evaluate/health")
        assert response.status_code == 200
        data = response.json()
        assert "storageAccessible" in data or "storage_accessible" in data

    def test_liveness(self, unauth_client):
        """Test the Quarkus liveness probe endpoint."""
        response = unauth_client.get("/health/live")
        assert response.status_code == 200

    def test_readiness(self, unauth_client):
        """Test the Quarkus readiness probe endpoint."""
        response = unauth_client.get("/health/ready")
        assert response.status_code == 200
