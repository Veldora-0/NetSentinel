"""Tests for Phase 13 - Role-Based Access Control (RBAC).

Verifies:
- Public endpoints (/api/health, /api/ready, /api/auth/login) are accessible without authentication.
- Protected endpoints return 401 Unauthorized when unauthenticated.
- Malformed and invalid Authorization headers are rejected with 401.
- Role-based permissions are enforced strictly:
  * VIEWER has read-only access and is rejected (403) from mutations.
  * ANALYST can triage incidents and query threat intel, but is rejected (403) from firewall controls, FIM rebaseline, and user management.
  * ADMIN has full operational control over all endpoints.
"""

import os
import sys
import time
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app import create_app
from database import db
from detector import SecurityEvent
from auth.models import User
from auth.roles import Role, Permission
from auth.service import AuthService


@pytest.fixture
def rbac_app():
    """Create Flask app with in-memory DB and strict auth enforcement enabled."""
    app, socketio = create_app(start_capture=False)
    app.config["TESTING"] = True
    app.config["AUTH_ENFORCE_IN_TESTS"] = True

    with app.app_context():
        db.create_all()

        # Seed users for each role
        AuthService.create_user("test_viewer", "ViewerPass123!", Role.VIEWER)
        AuthService.create_user("test_analyst", "AnalystPass123!", Role.ANALYST)
        AuthService.create_user("test_admin", "AdminPass123!", Role.ADMIN)

        # Seed an incident for incident action tests
        ev = SecurityEvent(
            event_id="ev-rbac-01",
            timestamp=time.time(),
            detection_type="PORT_SCAN",
            severity="HIGH",
            source_ip="198.51.100.22",
            description="RBAC test incident trigger",
        )
        inc = app.incident_manager.correlate_security_event(ev)
        app.test_incident_id = inc.incident_id

    return app


@pytest.fixture
def rbac_client(rbac_app):
    return rbac_app.test_client()


def get_token_for(client, username, password):
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200
    return resp.get_json()["token"]


# ==============================================================================
# Public Endpoints & Unauthenticated Enforcement Tests
# ==============================================================================

def test_public_endpoints_accessible_without_auth(rbac_client):
    """Verify health, ready, and login endpoints do not require auth tokens."""
    r_health = rbac_client.get("/api/health")
    assert r_health.status_code == 200

    r_ready = rbac_client.get("/api/ready")
    assert r_ready.status_code in (200, 503)  # Ready or not ready, but not 401

    r_login = rbac_client.post("/api/auth/login", json={"username": "invalid", "password": "wrong"})
    assert r_login.status_code == 401  # Handled by login logic, not decorator


def test_protected_endpoints_require_auth(rbac_client, rbac_app):
    """Verify unauthenticated requests to protected endpoints return 401 Unauthorized."""
    inc_id = rbac_app.test_incident_id

    protected_gets = [
        "/api/system/status",
        "/api/metrics",
        "/api/alerts",
        "/api/events",
        "/api/ml/status",
        "/api/risk/recent",
        "/api/telemetry/current",
        "/api/host/status",
        "/api/network/status",
        "/api/firewall/status",
        "/api/firewall/blocked",
        "/api/incidents",
        f"/api/incidents/{inc_id}",
        "/api/fim/status",
        "/api/threat-intel/status",
    ]

    for ep in protected_gets:
        resp = rbac_client.get(ep)
        assert resp.status_code == 401, f"Expected 401 for GET {ep}, got {resp.status_code}"

    protected_posts = [
        ("/api/firewall/block", {"ip": "1.2.3.4"}),
        ("/api/firewall/unblock", {"ip": "1.2.3.4"}),
        (f"/api/incidents/{inc_id}/status", {"status": "ACKNOWLEDGED"}),
        ("/api/fim/rebaseline", {}),
        ("/api/threat-intel/ip/8.8.8.8/lookup", {}),
    ]

    for ep, payload in protected_posts:
        resp = rbac_client.post(ep, json=payload)
        assert resp.status_code == 401, f"Expected 401 for POST {ep}, got {resp.status_code}"


def test_malformed_auth_headers_rejected(rbac_client):
    """Verify improper Authorization headers return 401."""
    # Missing Bearer prefix
    r1 = rbac_client.get("/api/system/status", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert r1.status_code == 401

    # Empty token
    r2 = rbac_client.get("/api/system/status", headers={"Authorization": "Bearer "})
    assert r2.status_code == 401

    # Invalid token string
    r3 = rbac_client.get("/api/system/status", headers={"Authorization": "Bearer badtoken123"})
    assert r3.status_code == 401


# ==============================================================================
# Role-Based Permissions Tests (VIEWER, ANALYST, ADMIN)
# ==============================================================================

def test_viewer_role_permissions(rbac_client, rbac_app):
    """Verify VIEWER can read security dashboards but is blocked (403) from sensitive actions."""
    inc_id = rbac_app.test_incident_id
    token = get_token_for(rbac_client, "test_viewer", "ViewerPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    # VIEWER can read system status, metrics, events, incidents, fim, threat-intel
    assert rbac_client.get("/api/system/status", headers=headers).status_code == 200
    assert rbac_client.get("/api/metrics", headers=headers).status_code == 200
    assert rbac_client.get("/api/events", headers=headers).status_code == 200
    assert rbac_client.get("/api/incidents", headers=headers).status_code == 200
    assert rbac_client.get(f"/api/incidents/{inc_id}", headers=headers).status_code == 200
    assert rbac_client.get("/api/firewall/status", headers=headers).status_code == 200
    assert rbac_client.get("/api/fim/status", headers=headers).status_code == 200
    assert rbac_client.get("/api/threat-intel/status", headers=headers).status_code == 200

    # VIEWER cannot block or unblock firewall (403)
    r_block = rbac_client.post("/api/firewall/block", headers=headers, json={"ip": "198.51.100.99"})
    assert r_block.status_code == 403
    assert Permission.MANAGE_FIREWALL in r_block.get_json()["message"]

    r_unblock = rbac_client.post("/api/firewall/unblock", headers=headers, json={"ip": "198.51.100.99"})
    assert r_unblock.status_code == 403

    # VIEWER cannot mutate incidents (403)
    r_inc = rbac_client.post(f"/api/incidents/{inc_id}/status", headers=headers, json={"status": "ACKNOWLEDGED"})
    assert r_inc.status_code == 403
    assert Permission.MANAGE_INCIDENTS in r_inc.get_json()["message"]

    # VIEWER cannot trigger FIM rebaseline (403)
    r_fim = rbac_client.post("/api/fim/rebaseline", headers=headers, json={})
    assert r_fim.status_code == 403

    # VIEWER cannot query threat intel background lookup (403)
    r_ti = rbac_client.post("/api/threat-intel/ip/8.8.8.8/lookup", headers=headers)
    assert r_ti.status_code == 403

    # VIEWER cannot manage users (403)
    r_users = rbac_client.get("/api/auth/users", headers=headers)
    assert r_users.status_code == 403


def test_analyst_role_permissions(rbac_client, rbac_app):
    """Verify ANALYST can read and triage incidents, but cannot modify firewall or manage users."""
    inc_id = rbac_app.test_incident_id
    token = get_token_for(rbac_client, "test_analyst", "AnalystPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    # ANALYST can read
    assert rbac_client.get("/api/system/status", headers=headers).status_code == 200
    assert rbac_client.get("/api/incidents", headers=headers).status_code == 200

    # ANALYST can manage incidents
    r_ack = rbac_client.post(f"/api/incidents/{inc_id}/acknowledge", headers=headers, json={
        "analyst_note": "Analyst acknowledged incident",
    })
    assert r_ack.status_code == 200

    # ANALYST cannot modify firewall (403)
    r_block = rbac_client.post("/api/firewall/block", headers=headers, json={"ip": "198.51.100.99"})
    assert r_block.status_code == 403

    # ANALYST cannot rebaseline FIM (403)
    r_fim = rbac_client.post("/api/fim/rebaseline", headers=headers, json={})
    assert r_fim.status_code == 403

    # ANALYST cannot access user management (403)
    r_users = rbac_client.get("/api/auth/users", headers=headers)
    assert r_users.status_code == 403


def test_admin_role_permissions(rbac_client, rbac_app):
    """Verify ADMIN has permissions across all endpoints."""
    inc_id = rbac_app.test_incident_id
    token = get_token_for(rbac_client, "test_admin", "AdminPass123!")
    headers = {"Authorization": f"Bearer {token}"}

    # ADMIN can read
    assert rbac_client.get("/api/system/status", headers=headers).status_code == 200

    # ADMIN can manage incidents
    r_res = rbac_client.post(f"/api/incidents/{inc_id}/resolve", headers=headers, json={
        "resolution": "Admin resolved incident",
    })
    assert r_res.status_code == 200

    # ADMIN can manage firewall (dry-run mode)
    r_block = rbac_client.post("/api/firewall/block", headers=headers, json={
        "ip": "198.51.100.77",
        "reason": "Admin test block",
    })
    assert r_block.status_code == 200

    r_unblock = rbac_client.post("/api/firewall/unblock", headers=headers, json={
        "ip": "198.51.100.77",
    })
    assert r_unblock.status_code == 200

    # ADMIN can trigger FIM rebaseline
    r_fim = rbac_client.post("/api/fim/rebaseline", headers=headers, json={})
    assert r_fim.status_code == 200

    # ADMIN can manage users
    r_users = rbac_client.get("/api/auth/users", headers=headers)
    assert r_users.status_code == 200
    assert len(r_users.get_json()["users"]) >= 3
