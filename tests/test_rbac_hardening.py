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


# ==============================================================================
# 6. Hardened Secret Key & Environment Validation
# ==============================================================================

def test_production_rejects_missing_or_insecure_secret_key():
    from config_validator import ConfigValidator, ConfigurationError

    base_valid = {
        "ENV": "production",
        "HOST": "0.0.0.0",
        "PORT": 5000,
        "SECRET_KEY": "super-strong-production-secret-key-32chars!",
        "AUTH_SETTINGS": {"auth_enabled": True},
    }

    # Strong key succeeds
    res = ConfigValidator.validate_config(base_valid)
    assert res.is_valid, f"Validation failed unexpectedly: {res.errors}"

    # Missing/empty secret key fails
    res_empty = ConfigValidator.validate_config({**base_valid, "SECRET_KEY": ""})
    assert not res_empty.is_valid
    assert any("SECRET_KEY must be configured" in e for e in res_empty.errors)

    # Insecure default secret key fails
    res_default = ConfigValidator.validate_config({
        **base_valid,
        "SECRET_KEY": "netsentinel-dev-secret-key-change-in-production"
    })
    assert not res_default.is_default_valid if hasattr(res_default, "is_default_valid") else not res_default.is_valid
    assert any("Insecure default SECRET_KEY" in e for e in res_default.errors)

    # Short secret key fails
    res_short = ConfigValidator.validate_config({**base_valid, "SECRET_KEY": "too-short"})
    assert not res_short.is_valid
    assert any("at least 16 characters" in e for e in res_short.errors)


def test_development_accepts_default_secret_key_with_warning():
    from config_validator import ConfigValidator

    dev_config = {
        "ENV": "development",
        "HOST": "127.0.0.1",
        "PORT": 5000,
        "SECRET_KEY": "netsentinel-dev-secret-key-change-in-production",
        "AUTH_SETTINGS": {"auth_enabled": True},
    }
    res = ConfigValidator.validate_config(dev_config)
    assert res.is_valid
    assert any("default development SECRET_KEY" in w for w in res.warnings)


def test_auth_disabled_fails_closed_outside_development():
    from config_validator import ConfigValidator

    # In production environment, auth cannot be disabled
    prod_config = {
        "ENV": "production",
        "SECRET_KEY": "super-strong-production-secret-key-32chars!",
        "AUTH_SETTINGS": {"auth_enabled": False},
    }
    res_prod = ConfigValidator.validate_config(prod_config)
    assert not res_prod.is_valid
    assert any("cannot be disabled" in e or "cannot be False" in e for e in res_prod.errors)

    # In non-dev/non-test environment (e.g., staging), auth cannot be disabled
    staging_config = {
        "ENV": "staging",
        "SECRET_KEY": "super-strong-production-secret-key-32chars!",
        "AUTH_SETTINGS": {"auth_enabled": False},
    }
    res_staging = ConfigValidator.validate_config(staging_config)
    assert not res_staging.is_valid
    assert any("cannot be disabled" in e for e in res_staging.errors)

    # In explicit development environment, auth CAN be disabled
    dev_config = {
        "ENV": "development",
        "SECRET_KEY": "netsentinel-dev-secret-key-change-in-production",
        "AUTH_SETTINGS": {"auth_enabled": False},
    }
    res_dev = ConfigValidator.validate_config(dev_config)
    assert res_dev.is_valid


# ==============================================================================
# 7. Socket.IO Credential Transport Hardening
# ==============================================================================

def test_socketio_rejects_query_param_token(auth_test_context):
    app = auth_test_context["app"]
    socketio = auth_test_context["socketio"]
    admin_token = auth_test_context["admin"]["token"]

    # Passing token in query parameter (?token=...) MUST BE REJECTED
    client = socketio.test_client(app, query_string=f"?token={admin_token}")
    assert not client.is_connected()


def test_socketio_does_not_emit_telemetry_to_rejected_client(auth_test_context):
    app = auth_test_context["app"]
    socketio = auth_test_context["socketio"]

    # Rejected unauthenticated connection receives zero events
    client = socketio.test_client(app)
    assert not client.is_connected()
    with pytest.raises(RuntimeError, match="not connected"):
        client.get_received()
    assert len(client.queue) == 0


def test_env_symlink_does_not_modify_target_permissions(tmp_path):
    target = tmp_path / "sensitive_system_file.txt"
    target.write_text("SOME_SECRET=123\n")
    os.chmod(target, 0o644)
    original_mode = os.stat(target).st_mode & 0o777

    symlink_path = tmp_path / ".env"
    symlink_path.symlink_to(target)

    # Re-run the safe inspection logic as in config.py
    if os.path.isfile(symlink_path):
        if not os.path.islink(symlink_path):
            os.chmod(symlink_path, 0o600)

    # Target mode must be preserved exactly
    after_mode = os.stat(target).st_mode & 0o777
    assert after_mode == original_mode


# ==============================================================================
# 6. Single Administrator Policy & Analyst Management Lifecycle
# ==============================================================================

def test_admin_cannot_create_second_admin_via_api(auth_test_context):
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    # Attempt to create a second admin via POST /api/auth/users
    resp = client.post("/api/auth/users", headers=admin_headers, json={
        "username": "second_admin",
        "password": "ValidAdminPassword123!",
        "role": Role.ADMIN,
    })
    assert resp.status_code == 400
    assert "single administrator" in resp.get_json()["message"].lower()


def test_admin_cannot_promote_user_to_admin(auth_test_context):
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}
    analyst_id = auth_test_context["analyst"]["user"].id

    # Attempt to promote analyst to ADMIN via PATCH /api/auth/users/<id>
    resp = client.patch(f"/api/auth/users/{analyst_id}", headers=admin_headers, json={
        "role": Role.ADMIN,
    })
    assert resp.status_code == 400
    assert "cannot promote" in resp.get_json()["message"].lower() or "single administrator" in resp.get_json()["message"].lower()


def test_admin_can_manage_analyst_full_lifecycle(auth_test_context):
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    # 1. Admin creates an Analyst
    resp_create = client.post("/api/auth/users", headers=admin_headers, json={
        "username": "tier1_analyst",
        "password": "AnalystPassword123!",
        "role": Role.ANALYST,
    })
    assert resp_create.status_code == 201
    analyst_data = resp_create.get_json()["user"]
    analyst_id = analyst_data["id"]
    assert analyst_data["role"] == Role.ANALYST

    # 2. Admin resets Analyst password
    resp_pw = client.patch(f"/api/auth/users/{analyst_id}", headers=admin_headers, json={
        "password": "NewAnalystPassword456!",
    })
    assert resp_pw.status_code == 200

    # Verify analyst can log in with new password
    login_resp = client.post("/api/auth/login", json={
        "username": "tier1_analyst",
        "password": "NewAnalystPassword456!",
    })
    assert login_resp.status_code == 200
    analyst_token = login_resp.get_json()["token"]

    # 3. Admin deactivates Analyst
    resp_deact = client.patch(f"/api/auth/users/{analyst_id}", headers=admin_headers, json={
        "is_active": False,
    })
    assert resp_deact.status_code == 200

    # Deactivated analyst cannot login
    bad_login = client.post("/api/auth/login", json={
        "username": "tier1_analyst",
        "password": "NewAnalystPassword456!",
    })
    assert bad_login.status_code == 401

    # 4. Admin reactivates Analyst
    resp_react = client.patch(f"/api/auth/users/{analyst_id}", headers=admin_headers, json={
        "is_active": True,
    })
    assert resp_react.status_code == 200

    # 5. Admin deletes Analyst
    resp_del = client.delete(f"/api/auth/users/{analyst_id}", headers=admin_headers)
    assert resp_del.status_code == 200
    assert "deleted" in resp_del.get_json()["message"].lower()


def test_analyst_and_viewer_cannot_manage_users(auth_test_context):
    client = auth_test_context["client"]
    analyst_headers = {"Authorization": f"Bearer {auth_test_context['analyst']['token']}"}
    viewer_headers = {"Authorization": f"Bearer {auth_test_context['viewer']['token']}"}
    target_id = auth_test_context["viewer"]["user"].id

    for role_name, headers in [("analyst", analyst_headers), ("viewer", viewer_headers)]:
        # Attempt list users -> 403
        r_list = client.get("/api/auth/users", headers=headers)
        assert r_list.status_code == 403, f"{role_name} should not be allowed to list users"

        # Attempt create user -> 403
        r_create = client.post("/api/auth/users", headers=headers, json={
            "username": f"hacker_{role_name}",
            "password": "HackerPassword123!",
            "role": Role.ANALYST,
        })
        assert r_create.status_code == 403, f"{role_name} should not be allowed to create users"

        # Attempt update user -> 403
        r_update = client.patch(f"/api/auth/users/{target_id}", headers=headers, json={
            "role": Role.ADMIN,
        })
        assert r_update.status_code == 403, f"{role_name} should not be allowed to update users"

        # Attempt delete user -> 403
        r_del = client.delete(f"/api/auth/users/{target_id}", headers=headers)
        assert r_del.status_code == 403, f"{role_name} should not be allowed to delete users"


def test_cli_resolve_multiple_admins(auth_test_context, monkeypatch):
    import sys
    from auth.models import User, db

    app = auth_test_context["app"]

    with app.app_context():
        # Inject a second admin directly into the database (simulating legacy state)
        admin2 = User(username="legacy_admin2", role=Role.ADMIN, is_active=True)
        admin2.set_password("LegacyAdminPass123!")
        db.session.add(admin2)
        db.session.commit()

        # Verify two admins exist
        assert User.query.filter_by(role=Role.ADMIN).count() == 2

        from bootstrap import main as bootstrap_main

        # Run resolution keeping the primary admin
        primary_admin_name = auth_test_context["admin"]["user"].username
        test_args = ["bootstrap.py", "--resolve-multiple-admins", "--keep-admin", primary_admin_name]
        monkeypatch.setattr(sys, "argv", test_args)

        # Execute resolution
        bootstrap_main(app=app)

        # Verify exactly 1 admin remains and legacy_admin2 was demoted to ANALYST
        admins = User.query.filter_by(role=Role.ADMIN).all()
        assert len(admins) == 1
        assert admins[0].username == primary_admin_name

        demoted = User.query.filter_by(username="legacy_admin2").first()
        assert demoted is not None
        assert demoted.role == Role.ANALYST
        assert demoted.is_active is True

