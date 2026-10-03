"""Unit tests for NetSentinel Backend Health API."""

import pytest
import sys
import os

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app import create_app


@pytest.fixture
def client():
    """Create Flask test client fixture."""
    app, _ = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health_endpoint(client):
    """Test GET /api/health endpoint returns 200 OK and expected JSON schema."""
    response = client.get("/api/health")
    assert response.status_code == 200
    
    data = response.get_json()
    assert data is not None
    assert data.get("status") == "ok"
    assert data.get("service") == "NetSentinel Backend"
