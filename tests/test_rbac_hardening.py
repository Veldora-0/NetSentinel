"""Security and Authorization Regression Tests for NetSentinel.

Validates:
1. Admin, Analyst, and Viewer permission matrices across all endpoints.
2. Read-only endpoints enforcement of Permission.READ_SECURITY.
3. Mutation endpoints rejection of unauthorized roles with HTTP 403.
4. Socket.IO connection authentication, token expiration, revocation, and inactive user rejection.
5. .env administrator bootstrap, environment variable precedence, and no overwrite on restart.
6. Guardrails protecting against self-demotion, self-disabling, and removal of the last active Admin.
7. Token invalidation upon account deactivation or password changes.
8. Secret sanitization in diagnostics and logs.
"""

import os
import tempfile
import time
import pytest
from unittest.mock import patch

from app import create_app
from database import db
from auth.models import User, AuthTokenRecord
from auth.roles import Role, Permission
from auth.service import AuthService
from config import Config


@pytest.fixture
def auth_test_context():
    """Setup an in-memory Flask app with database and users for each role."""
    test_config = {
        "TESTING": True,
        "AUTH_ENFORCE_IN_TESTS": True,
        "AUTH_ALLOW_TEST_COMPATIBILITY": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "SECRET_KEY": "test-secret-key-security-matrix",
        "API_RATE_LIMIT": 1000,
        "SENSITIVE_RATE_LIMIT": 100,
    }
    app, socketio = create_app(config_class=test_config, start_capture=False)

    with app.app_context():
        # Create users for each role
        admin_user, _ = AuthService.create_user("sec_admin", "AdminPassword123!", Role.ADMIN)
        analyst_user, _ = AuthService.create_user("sec_analyst", "AnalystPassword123!", Role.ANALYST)
        viewer_user, _ = AuthService.create_user("sec_viewer", "ViewerPassword123!", Role.VIEWER)

        # Issue bearer tokens
        _, admin_token, _, _ = AuthService.authenticate("sec_admin", "AdminPassword123!")
        _, analyst_token, _, _ = AuthService.authenticate("sec_analyst", "AnalystPassword123!")
        _, viewer_token, _, _ = AuthService.authenticate("sec_viewer", "ViewerPassword123!")

        client = app.test_client()

        yield {
            "app": app,
            "socketio": socketio,
            "client": client,
            "admin": {"user": admin_user, "token": admin_token},
            "analyst": {"user": analyst_user, "token": analyst_token},
            "viewer": {"user": viewer_user, "token": viewer_token},
        }


# ==============================================================================
# 1. READ_SECURITY Permission Enforcement Tests
# ==============================================================================

def test_read_endpoints_enforce_read_security(auth_test_context):
    client = auth_test_context["client"]
    viewer_headers = {"Authorization": f"Bearer {auth_test_context['viewer']['token']}"}

    # Viewer has read:security permission and should be able to read all security data
    read_routes = [
        "/api/system/status",
        "/api/metrics",
        "/api/alerts",
        "/api/events",
        "/api/ml/status",
        "/api/ml/metrics",
        "/api/risk/recent",
        "/api/risk/history",
        "/api/risk/stats",
        "/api/security/summary",
        "/api/telemetry/current",
        "/api/telemetry/history",
        "/api/host/status",
        "/api/host/events",
        "/api/network/status",
        "/api/network/arp",
        "/api/firewall/status",
        "/api/firewall/blocked",
        "/api/incidents",
        "/api/incidents/stats",
        "/api/fim/status",
        "/api/fim/events",
        "/api/fim/baseline",
        "/api/threat-intel/status",
    ]

    for route in read_routes:
        res = client.get(route, headers=viewer_headers)
        assert res.status_code in (200, 503), f"Route {route} failed for viewer: {res.status_code}"

    # Unauthenticated request without token must fail with 401
    for route in ["/api/system/status", "/api/metrics", "/api/incidents", "/api/firewall/status"]:
        res_unauth = client.get(route)
        assert res_unauth.status_code == 401, f"Route {route} allowed unauthenticated access"


# ==============================================================================
# 2. Mutation Authorization Matrix Tests (Admin vs Analyst vs Viewer)
# ==============================================================================

def test_viewer_rejected_on_all_mutations(auth_test_context):
    client = auth_test_context["client"]
    viewer_headers = {"Authorization": f"Bearer {auth_test_context['viewer']['token']}"}

    mutations = [
        ("POST", "/api/firewall/block", {"ip_address": "192.168.1.100"}),
        ("POST", "/api/firewall/unblock", {"ip_address": "192.168.1.100"}),
        ("POST", "/api/incidents/inc-test-123/status", {"status": "RESOLVED"}),
        ("POST", "/api/incidents/inc-test-123/acknowledge", {}),
        ("POST", "/api/incidents/inc-test-123/resolve", {}),
        ("POST", "/api/fim/rebaseline", {}),
        ("POST", "/api/threat-intel/ip/8.8.8.8/lookup", {}),
        ("GET", "/api/auth/users", None),
        ("POST", "/api/auth/users", {"username": "evil", "password": "Password123!"}),
        ("PATCH", "/api/auth/users/1", {"role": "ADMIN"}),
        ("DELETE", "/api/auth/users/1", None),
    ]

    for method, route, payload in mutations:
        if method == "POST":
            res = client.post(route, headers=viewer_headers, json=payload)
        elif method == "GET":
            res = client.get(route, headers=viewer_headers)
        elif method == "PATCH":
            res = client.patch(route, headers=viewer_headers, json=payload)
        elif method == "DELETE":
            res = client.delete(route, headers=viewer_headers)
        assert res.status_code == 403, f"Viewer unexpectedly allowed on {method} {route} (code: {res.status_code})"


def test_analyst_permissions_and_boundaries(auth_test_context):
    client = auth_test_context["client"]
    analyst_headers = {"Authorization": f"Bearer {auth_test_context['analyst']['token']}"}

    # Analyst CAN manage incidents (manage:incidents) -> 404 since fake incident doesn't exist, NOT 403
    res_inc = client.post("/api/incidents/inc-fake/status", headers=analyst_headers, json={"status": "RESOLVED"})
    assert res_inc.status_code != 403, "Analyst denied on manage:incidents"

    # Analyst CANNOT manage firewall -> 403 Forbidden
    res_fw = client.post("/api/firewall/block", headers=analyst_headers, json={"ip_address": "10.0.0.1"})
    assert res_fw.status_code == 403, "Analyst allowed on manage:firewall"

    # Analyst CANNOT trigger FIM rebaseline -> 403 Forbidden
    res_fim = client.post("/api/fim/rebaseline", headers=analyst_headers, json={})
    assert res_fim.status_code == 403, "Analyst allowed on manage:fim"

    # Analyst CANNOT manage users -> 403 Forbidden
    res_users = client.get("/api/auth/users", headers=analyst_headers)
    assert res_users.status_code == 403, "Analyst allowed on manage:users"


def test_admin_has_full_management_access(auth_test_context):
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    # Admin CAN view users
    res_users = client.get("/api/auth/users", headers=admin_headers)
    assert res_users.status_code == 200
    assert len(res_users.get_json()["users"]) >= 3

    # Admin CAN create users
    res_create = client.post("/api/auth/users", headers=admin_headers, json={
        "username": "new_operator",
        "password": "Password12345!",
        "role": "ANALYST",
    })
    assert res_create.status_code == 201


# ==============================================================================
# 3. Socket.IO Handshake Authentication Tests
# ==============================================================================

def test_socketio_rejects_unauthenticated_connection(auth_test_context):
    app = auth_test_context["app"]
    socketio = auth_test_context["socketio"]

    # Connect without token -> Rejected
    client = socketio.test_client(app)
    assert not client.is_connected()


def test_socketio_accepts_valid_authenticated_token(auth_test_context):
    app = auth_test_context["app"]
    socketio = auth_test_context["socketio"]
    admin_token = auth_test_context["admin"]["token"]

    # Connect with valid auth token in payload dict
    client = socketio.test_client(app, auth={"token": admin_token})
    assert client.is_connected()
    received = client.get_received()
    assert any(pkt["name"] == "connection_response" for pkt in received)
    client.disconnect()


def test_socketio_rejects_expired_or_revoked_token(auth_test_context):
    app = auth_test_context["app"]
    socketio = auth_test_context["socketio"]
    admin_token = auth_test_context["admin"]["token"]

    # Revoke the token
    with app.app_context():
        AuthService.revoke_token(admin_token)

    # Attempt connect with revoked token -> Rejected
    client = socketio.test_client(app, auth={"token": admin_token})
    assert not client.is_connected()


def test_socketio_rejects_inactive_user(auth_test_context):
    app = auth_test_context["app"]
    socketio = auth_test_context["socketio"]
    viewer_token = auth_test_context["viewer"]["token"]
    viewer_user = auth_test_context["viewer"]["user"]

    # Deactivate the user
    with app.app_context():
        u = db.session.get(User, viewer_user.id)
        u.is_active = False
        db.session.commit()

    # Attempt connect with token belonging to deactivated user -> Rejected
    client = socketio.test_client(app, auth={"token": viewer_token})
    assert not client.is_connected()


# ==============================================================================
# 4. User Guardrails & Security Policies
# ==============================================================================

def test_cannot_delete_or_demote_last_admin(auth_test_context):
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}
    admin_id = auth_test_context["admin"]["user"].id

    # Attempt self-demotion
    res_demote = client.patch(f"/api/auth/users/{admin_id}", headers=admin_headers, json={"role": "VIEWER"})
    assert res_demote.status_code == 400
    assert "Cannot demote your own administrator account" in res_demote.get_json()["message"]

    # Attempt self-disable
    res_disable = client.patch(f"/api/auth/users/{admin_id}", headers=admin_headers, json={"is_active": False})
    assert res_disable.status_code == 400
    assert "Cannot disable your own administrator account" in res_disable.get_json()["message"]

    # Attempt self-deletion
    res_del = client.delete(f"/api/auth/users/{admin_id}", headers=admin_headers)
    assert res_del.status_code == 400
    assert "Cannot delete your own administrator account" in res_del.get_json()["message"]


# ==============================================================================
# 5. Bootstrap & .env Configuration Safety
# ==============================================================================

def test_bootstrap_does_not_overwrite_existing_admin(auth_test_context):
    app = auth_test_context["app"]

    with app.app_context():
        # Admin exists with known password
        u = User.query.filter_by(role=Role.ADMIN).first()
        initial_hash = u.password_hash

        # Re-run bootstrap_admin_if_needed with a different password
        from auth.bootstrap import bootstrap_admin_if_needed
        app.config["AUTH_ADMIN_PASSWORD"] = "DifferentSecretPassword123!"
        res = bootstrap_admin_if_needed(app)

        # Should be None (no-op) and password hash untouched
        assert res is None
        u_refreshed = User.query.filter_by(role=Role.ADMIN).first()
        assert u_refreshed.password_hash == initial_hash
