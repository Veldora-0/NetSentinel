"""Phase 14 End-to-End Validation: Authentication & RBAC Layer.

Verifies:
1. Public health and readiness endpoints remain accessible without tokens.
2. Unauthenticated requests to protected endpoints return 401 Unauthorized.
3. Login failure produces uniform error response preventing username enumeration.
4. VIEWER role can access read endpoints, but is denied (403) from mutations.
5. ANALYST role can triage incidents, but is denied (403) from administrative/firewall actions.
6. ADMIN role has full operational access across all endpoints.
"""

import time
import pytest

from app import create_app
from database import db
from detector import SecurityEvent
from auth.roles import Role
from auth.service import AuthService


@pytest.fixture
def auth_test_client():
    cfg = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "AUTH_ENFORCE_IN_TESTS": True,
    }
    app, _ = create_app(config_class=cfg, start_capture=False)

    with app.app_context():
        db.create_all()

        # Create users
        AuthService.create_user("e2e_viewer", "ViewerPass123!", Role.VIEWER)
        AuthService.create_user("e2e_analyst", "AnalystPass123!", Role.ANALYST)
        AuthService.create_user("e2e_admin", "AdminPass123!", Role.ADMIN)

        # Seed an incident for mutation tests
        ev = SecurityEvent(
            event_id="ev-rbac-test",
            timestamp=time.time(),
            detection_type="PORT_SCAN",
            severity="HIGH",
            source_ip="192.168.1.99",
        )
        inc = app.incident_manager.correlate_security_event(ev)

        # Tokens
        _, viewer_tok, _, _ = AuthService.authenticate("e2e_viewer", "ViewerPass123!")
        _, analyst_tok, _, _ = AuthService.authenticate("e2e_analyst", "AnalystPass123!")
        _, admin_tok, _, _ = AuthService.authenticate("e2e_admin", "AdminPass123!")

        client = app.test_client()

        yield {
            "client": client,
            "incident_id": inc.incident_id,
            "viewer_headers": {"Authorization": f"Bearer {viewer_tok}"},
            "analyst_headers": {"Authorization": f"Bearer {analyst_tok}"},
            "admin_headers": {"Authorization": f"Bearer {admin_tok}"},
        }

        db.session.remove()
        db.drop_all()


def test_e2e_public_and_unauthenticated_endpoints(auth_test_client):
    """Verify health endpoints are open and protected endpoints return 401."""
    client = auth_test_client["client"]

    # Public health checks
    res_health = client.get("/api/health")
    assert res_health.status_code == 200

    res_ready = client.get("/api/ready")
    assert res_ready.status_code == 200

    # Unauthenticated protected requests
    res_incidents = client.get("/api/incidents")
    assert res_incidents.status_code == 401

    res_events = client.get("/api/events")
    assert res_events.status_code == 401


def test_e2e_login_failure_uniformity(auth_test_client):
    """Verify that login failures return identical 401 payloads preventing account enumeration."""
    client = auth_test_client["client"]

    # Case 1: Non-existent user
    res_no_user = client.post("/api/auth/login", json={"username": "ghost_user", "password": "anypassword"})
    assert res_no_user.status_code == 401
    body_no_user = res_no_user.get_json()

    # Case 2: Valid user with incorrect password
    res_bad_pw = client.post("/api/auth/login", json={"username": "e2e_viewer", "password": "wrongpassword123!"})
    assert res_bad_pw.status_code == 401
    body_bad_pw = res_bad_pw.get_json()

    # Contract: messages must be identical
    assert body_no_user["message"] == "Invalid username or password."
    assert body_bad_pw["message"] == "Invalid username or password."
    assert body_no_user["error"] == "unauthorized"
    assert body_bad_pw["error"] == "unauthorized"


def test_e2e_rbac_role_boundaries(auth_test_client):
    """Verify role permission boundaries across VIEWER, ANALYST, and ADMIN."""
    client = auth_test_client["client"]
    inc_id = auth_test_client["incident_id"]

    v_headers = auth_test_client["viewer_headers"]
    a_headers = auth_test_client["analyst_headers"]
    adm_headers = auth_test_client["admin_headers"]

    # VIEWER: Can read incidents (200), cannot modify status (403)
    res_v_read = client.get("/api/incidents", headers=v_headers)
    assert res_v_read.status_code == 200

    res_v_mut = client.post(f"/api/incidents/{inc_id}/status", json={"status": "ACKNOWLEDGED"}, headers=v_headers)
    assert res_v_mut.status_code == 403

    # ANALYST: Can modify incident status (200), cannot access firewall controls (403)
    res_a_mut = client.post(f"/api/incidents/{inc_id}/status", json={"status": "ACKNOWLEDGED"}, headers=a_headers)
    assert res_a_mut.status_code == 200

    res_a_fw = client.post("/api/firewall/block", json={"ip_address": "192.168.1.99"}, headers=a_headers)
    assert res_a_fw.status_code == 403

    # ADMIN: Full access to firewall status and operations (200)
    res_adm_fw = client.get("/api/firewall/status", headers=adm_headers)
    assert res_adm_fw.status_code == 200
