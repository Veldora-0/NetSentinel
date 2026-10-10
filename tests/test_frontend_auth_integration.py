"""Frontend Authentication & RBAC Integration Tests.

Validates the full API contract expected by the NetSentinel frontend:
1. Login flow (/api/auth/login) with valid and invalid credentials.
2. Current user profile and permissions retrieval (/api/auth/me).
3. Session invalidation on logout (/api/auth/logout).
4. Role-Based Access Control (RBAC) boundaries aligned with UI capabilities:
   - VIEWER: Read-only access; mutations prohibited (403 Forbidden).
   - ANALYST: Incident triage and threat intel lookups permitted; firewall/FIM mutations prohibited (403 Forbidden).
   - ADMIN: Full management privileges across all protected operational boundaries.
"""

import time
import pytest
from app import create_app
from database import db
from detector import SecurityEvent
from auth.roles import Role, Permission
from auth.service import AuthService


@pytest.fixture
def auth_integration_client():
    """Create test client with enforced authentication and pre-seeded test accounts."""
    cfg = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "AUTH_ENFORCE_IN_TESTS": True,
        "FIREWALL_ENABLED": False,
    }
    app, _ = create_app(config_class=cfg, start_capture=False)

    with app.app_context():
        db.create_all()

        # Seed roles
        AuthService.create_user("fe_viewer", "ViewerPassword123!", Role.VIEWER)
        AuthService.create_user("fe_analyst", "AnalystPassword123!", Role.ANALYST)
        AuthService.create_user("fe_admin", "AdminPassword123!", Role.ADMIN)

        # Seed an incident for triage tests
        ev = SecurityEvent(
            event_id="ev-fe-auth-test",
            timestamp=time.time(),
            detection_type="PORT_SCAN",
            severity="HIGH",
            source_ip="192.168.1.150",
        )
        incident = app.incident_manager.correlate_security_event(ev)

        client = app.test_client()

        yield {
            "client": client,
            "incident_id": incident.incident_id,
        }

        db.session.remove()
        db.drop_all()


def test_login_flow_contract(auth_integration_client):
    """Test login API responses consumed by frontend Login.jsx."""
    client = auth_integration_client["client"]

    # Missing credentials -> 400
    res_empty = client.post("/api/auth/login", json={})
    assert res_empty.status_code == 400
    assert "required" in res_empty.get_json()["message"].lower()

    # Invalid credentials -> 401
    res_bad = client.post(
        "/api/auth/login",
        json={"username": "fe_admin", "password": "WrongPassword!"},
    )
    assert res_bad.status_code == 401
    assert "invalid" in res_bad.get_json()["message"].lower()

    # Successful login -> 200 with token, user, permissions
    res_ok = client.post(
        "/api/auth/login",
        json={"username": "fe_admin", "password": "AdminPassword123!"},
    )
    assert res_ok.status_code == 200
    data = res_ok.get_json()
    assert data["status"] == "ok"
    assert "token" in data and len(data["token"]) >= 32
    assert "user" in data
    assert data["user"]["username"] == "fe_admin"
    assert data["user"]["role"] == "ADMIN"
    assert Permission.MANAGE_FIREWALL in data["user"]["permissions"]
    assert Permission.MANAGE_INCIDENTS in data["user"]["permissions"]
    assert Permission.READ_SECURITY in data["user"]["permissions"]


def test_me_endpoint_and_token_validation(auth_integration_client):
    """Test /api/auth/me token verification consumed on frontend page load."""
    client = auth_integration_client["client"]

    # 1. Unauthenticated request -> 401
    res_no_auth = client.get("/api/auth/me")
    assert res_no_auth.status_code == 401

    # 2. Login as Analyst
    login_res = client.post(
        "/api/auth/login",
        json={"username": "fe_analyst", "password": "AnalystPassword123!"},
    )
    token = login_res.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Authenticated profile retrieval -> 200
    res_me = client.get("/api/auth/me", headers=headers)
    assert res_me.status_code == 200
    me_data = res_me.get_json()
    assert me_data["status"] == "ok"
    assert me_data["user"]["username"] == "fe_analyst"
    assert me_data["user"]["role"] == "ANALYST"
    assert Permission.MANAGE_INCIDENTS in me_data["user"]["permissions"]
    assert Permission.MANAGE_FIREWALL not in me_data["user"]["permissions"]

    # 4. Forged token -> 401
    res_fake = client.get("/api/auth/me", headers={"Authorization": "Bearer deadbeef000011112222333344445555"})
    assert res_fake.status_code == 401


def test_logout_session_invalidation(auth_integration_client):
    """Test logout flow invalidates the bearer token permanently."""
    client = auth_integration_client["client"]

    # Login
    login_res = client.post(
        "/api/auth/login",
        json={"username": "fe_viewer", "password": "ViewerPassword123!"},
    )
    token = login_res.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify session is valid
    res_check = client.get("/api/auth/me", headers=headers)
    assert res_check.status_code == 200

    # Logout
    logout_res = client.post("/api/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    assert logout_res.get_json()["status"] == "ok"

    # Subsequent request using same token must be rejected with 401
    res_after = client.get("/api/auth/me", headers=headers)
    assert res_after.status_code == 401


def test_rbac_boundaries_for_frontend_actions(auth_integration_client):
    """Test role boundaries corresponding to conditional UI controls."""
    client = auth_integration_client["client"]
    incident_id = auth_integration_client["incident_id"]

    # Login tokens
    viewer_tok = client.post("/api/auth/login", json={"username": "fe_viewer", "password": "ViewerPassword123!"}).get_json()["token"]
    analyst_tok = client.post("/api/auth/login", json={"username": "fe_analyst", "password": "AnalystPassword123!"}).get_json()["token"]
    admin_tok = client.post("/api/auth/login", json={"username": "fe_admin", "password": "AdminPassword123!"}).get_json()["token"]

    vh = {"Authorization": f"Bearer {viewer_tok}"}
    ah = {"Authorization": f"Bearer {analyst_tok}"}
    adm_h = {"Authorization": f"Bearer {admin_tok}"}

    # 1. READ endpoints accessible by all authenticated roles
    assert client.get("/api/network/status", headers=vh).status_code == 200
    assert client.get("/api/network/status", headers=ah).status_code == 200
    assert client.get("/api/network/status", headers=adm_h).status_code == 200

    # 2. FIREWALL MUTATIONS: Only ADMIN allowed (VIEWER and ANALYST get 403)
    block_payload = {"ip": "198.51.100.77", "duration": 300, "reason": "Test block"}
    assert client.post("/api/firewall/block", json=block_payload, headers=vh).status_code == 403
    assert client.post("/api/firewall/block", json=block_payload, headers=ah).status_code == 403
    admin_block_res = client.post("/api/firewall/block", json=block_payload, headers=adm_h)
    assert admin_block_res.status_code == 200

    # 3. INCIDENT TRIAGE: ANALYST and ADMIN allowed, VIEWER gets 403
    ack_payload = {"analyst_note": "Investigating"}
    assert client.post(f"/api/incidents/{incident_id}/acknowledge", json=ack_payload, headers=vh).status_code == 403
    assert client.post(f"/api/incidents/{incident_id}/acknowledge", json=ack_payload, headers=ah).status_code == 200

    # 4. FIM RE-BASELINE: Only ADMIN allowed
    assert client.post("/api/fim/rebaseline", headers=vh).status_code == 403
    assert client.post("/api/fim/rebaseline", headers=ah).status_code == 403
    assert client.post("/api/fim/rebaseline", headers=adm_h).status_code == 200
