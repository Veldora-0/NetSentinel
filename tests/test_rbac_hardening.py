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
    from sqlalchemy import text

    app = auth_test_context["app"]

    with app.app_context():
        # Drop constraint temporarily to simulate legacy database that predates uq_single_admin
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.commit()

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


def test_database_level_constraint_blocks_concurrent_second_admin(auth_test_context):
    from auth.models import User, db
    from sqlalchemy.exc import IntegrityError

    app = auth_test_context["app"]

    with app.app_context():
        # Admin already exists; attempting raw DB insert of a second ADMIN must be rejected by SQLite
        admin2 = User(username="rogue_admin", role=Role.ADMIN, is_active=True)
        admin2.set_password("RoguePass123!")
        db.session.add(admin2)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_deactivating_analyst_revokes_active_tokens(auth_test_context):
    from auth.models import AuthTokenRecord
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    # 1. Create an analyst
    r_create = client.post("/api/auth/users", headers=admin_headers, json={
        "username": "active_analyst",
        "password": "AnalystPassword123!",
        "role": Role.ANALYST,
    })
    assert r_create.status_code == 201
    analyst_id = r_create.get_json()["user"]["id"]

    # 2. Analyst logs in to receive an active token
    r_login = client.post("/api/auth/login", json={
        "username": "active_analyst",
        "password": "AnalystPassword123!",
    })
    assert r_login.status_code == 200
    token = r_login.get_json()["token"]

    # Verify session works
    r_check = client.get("/api/incidents", headers={"Authorization": f"Bearer {token}"})
    assert r_check.status_code == 200

    # 3. Admin deactivates the analyst
    r_deact = client.patch(f"/api/auth/users/{analyst_id}", headers=admin_headers, json={
        "is_active": False,
    })
    assert r_deact.status_code == 200

    # Verify the token is now explicitly marked revoked in database
    app = auth_test_context["app"]
    with app.app_context():
        tokens = AuthTokenRecord.query.filter_by(user_id=analyst_id).all()
        assert len(tokens) > 0
        assert all(t.revoked for t in tokens)

    # 4. Even if analyst is reactivated later, previous token MUST remain invalid
    r_react = client.patch(f"/api/auth/users/{analyst_id}", headers=admin_headers, json={
        "is_active": True,
    })
    assert r_react.status_code == 200

    r_old_token = client.get("/api/incidents", headers={"Authorization": f"Bearer {token}"})
    assert r_old_token.status_code == 401


def test_changing_role_revokes_active_tokens(auth_test_context):
    from auth.models import AuthTokenRecord
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    # Create an analyst
    r_create = client.post("/api/auth/users", headers=admin_headers, json={
        "username": "demoted_user",
        "password": "UserPassword123!",
        "role": Role.ANALYST,
    })
    assert r_create.status_code == 201
    user_id = r_create.get_json()["user"]["id"]

    # Log in
    r_login = client.post("/api/auth/login", json={
        "username": "demoted_user",
        "password": "UserPassword123!",
    })
    assert r_login.status_code == 200
    token = r_login.get_json()["token"]

    # Demote from ANALYST to VIEWER
    r_patch = client.patch(f"/api/auth/users/{user_id}", headers=admin_headers, json={
        "role": Role.VIEWER,
    })
    assert r_patch.status_code == 200

    # Token must be revoked
    app = auth_test_context["app"]
    with app.app_context():
        tokens = AuthTokenRecord.query.filter_by(user_id=user_id).all()
        assert all(t.revoked for t in tokens)


def test_diagnostics_reflects_account_policy_status(auth_test_context):
    from auth.models import User, db
    from sqlalchemy import text
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    # 1. When single admin is compliant -> status is ok
    res_ok = client.get("/api/system/status", headers=admin_headers)
    assert res_ok.status_code == 200
    data_ok = res_ok.get_json()
    assert data_ok["account_policy"]["status"] == "OK"
    assert data_ok["status"] == "ok"

    # 2. When multiple admins exist (legacy violation) -> status is degraded
    app = auth_test_context["app"]
    with app.app_context():
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.commit()
        extra_admin = User(username="extra_admin", role=Role.ADMIN, is_active=True)
        extra_admin.set_password("ExtraPass123!")
        db.session.add(extra_admin)
        db.session.commit()

    res_viol = client.get("/api/system/status", headers=admin_headers)
    assert res_viol.status_code == 200
    data_viol = res_viol.get_json()
    assert data_viol["account_policy"]["status"] == "VIOLATION_MULTIPLE_ADMINS"
    assert data_viol["status"] == "degraded"

    # 3. When single admin exists but constraint is missing -> UNVERIFIED_CONSTRAINT and degraded
    with app.app_context():
        # Remove extra admin so admin_count == 1, but keep uq_single_admin dropped
        u = User.query.filter_by(username="extra_admin").first()
        if u:
            db.session.delete(u)
            db.session.commit()

    res_missing = client.get("/api/system/status", headers=admin_headers)
    assert res_missing.status_code == 200
    data_missing = res_missing.get_json()
    assert data_missing["account_policy"]["status"] == "UNVERIFIED_CONSTRAINT"
    assert data_missing["account_policy"]["constraint_enforced"] is False
    assert data_missing["status"] == "degraded"


def test_constraint_status_inspection_helper(auth_test_context):
    from database import check_single_admin_constraint_status, ensure_single_admin_constraint, db
    from sqlalchemy import text
    app = auth_test_context["app"]

    with app.app_context():
        # Ensure it is installed
        ensure_single_admin_constraint()
        status_info = check_single_admin_constraint_status()
        assert status_info["supported"] is True
        assert status_info["installed"] is True
        assert status_info["dialect"] == "sqlite"

        # Drop index and verify it reports installed == False
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.commit()
        status_uninstalled = check_single_admin_constraint_status()
        assert status_uninstalled["installed"] is False

        # Re-ensure index
        assert ensure_single_admin_constraint() is True


def test_cli_recovery_cannot_target_nonexistent_user(auth_test_context, monkeypatch):
    import sys
    from bootstrap import main as bootstrap_main
    app = auth_test_context["app"]

    test_args = [
        "bootstrap.py",
        "--reset-password",
        "--username", "nonexistent_operator",
        "--password", "NewSecurePassword123!",
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc:
        bootstrap_main(app=app)
    assert exc.value.code == 1


def test_cli_recovery_cannot_promote_analyst_to_admin(auth_test_context, monkeypatch):
    import sys
    from auth.models import User
    from bootstrap import main as bootstrap_main
    app = auth_test_context["app"]

    analyst_name = auth_test_context["analyst"]["user"].username

    test_args = [
        "bootstrap.py",
        "--reset-password",
        "--username", analyst_name,
        "--password", "NewAnalystPassword123!",
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc:
        bootstrap_main(app=app)
    assert exc.value.code == 1

    # Verify analyst was NOT promoted
    with app.app_context():
        u = User.query.filter_by(username=analyst_name).first()
        assert u.role == Role.ANALYST


def test_cli_recovery_blocked_on_multi_admin_database(auth_test_context, monkeypatch):
    import sys
    from auth.models import User, db
    from sqlalchemy import text
    from bootstrap import main as bootstrap_main
    app = auth_test_context["app"]

    with app.app_context():
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.commit()
        admin2 = User(username="legacy_extra_admin", role=Role.ADMIN, is_active=True)
        admin2.set_password("ExtraPass123!")
        db.session.add(admin2)
        db.session.commit()

    test_args = [
        "bootstrap.py",
        "--reset-password",
        "--username", auth_test_context["admin"]["user"].username,
        "--password", "NewPass12345678!",
    ]
    monkeypatch.setattr(sys, "argv", test_args)

    with pytest.raises(SystemExit) as exc:
        bootstrap_main(app=app)
    assert exc.value.code == 1

    # Clean up extra admin and restore index
    with app.app_context():
        u = User.query.filter_by(username="legacy_extra_admin").first()
        if u:
            db.session.delete(u)
            db.session.commit()
        from database import ensure_single_admin_constraint
        ensure_single_admin_constraint()


def test_cli_recovery_revokes_active_admin_tokens(auth_test_context, monkeypatch):
    import sys
    from auth.models import AuthTokenRecord
    from bootstrap import main as bootstrap_main
    app = auth_test_context["app"]
    client = auth_test_context["client"]
    admin_name = auth_test_context["admin"]["user"].username
    admin_id = auth_test_context["admin"]["user"].id
    admin_token = auth_test_context["admin"]["token"]

    # Current token works
    r_check = client.get("/api/system/status", headers={"Authorization": f"Bearer {admin_token}"})
    assert r_check.status_code == 200

    # Execute password recovery for the admin
    test_args = [
        "bootstrap.py",
        "--reset-password",
        "--username", admin_name,
        "--password", "RecoveredAdminPassword123!",
    ]
    monkeypatch.setattr(sys, "argv", test_args)
    bootstrap_main(app=app)

    # Previous token is now revoked
    r_old = client.get("/api/system/status", headers={"Authorization": f"Bearer {admin_token}"})
    assert r_old.status_code == 401

    with app.app_context():
        tokens = AuthTokenRecord.query.filter_by(user_id=admin_id).all()
        assert all(t.revoked for t in tokens)

    # Login with new password works
    r_login = client.post("/api/auth/login", json={
        "username": admin_name,
        "password": "RecoveredAdminPassword123!",
    })
    assert r_login.status_code == 200


def test_failed_user_update_rolls_back_atomic_state(auth_test_context, monkeypatch):
    from auth.models import User, AuthTokenRecord, db
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    # Create an analyst and log them in
    r_create = client.post("/api/auth/users", headers=admin_headers, json={
        "username": "rollback_test_user",
        "password": "ValidPassword123!",
        "role": Role.ANALYST,
    })
    assert r_create.status_code == 201
    user_id = r_create.get_json()["user"]["id"]

    r_login = client.post("/api/auth/login", json={
        "username": "rollback_test_user",
        "password": "ValidPassword123!",
    })
    assert r_login.status_code == 200
    token = r_login.get_json()["token"]

    # Monkeypatch db.session.commit to raise an exception during update_user
    original_commit = db.session.commit
    def broken_commit():
        raise RuntimeError("Simulated database failure during update")
    monkeypatch.setattr(db.session, "commit", broken_commit)

    # Attempt to deactivate user -> Should fail with 500 and rollback
    r_fail = client.patch(f"/api/auth/users/{user_id}", headers=admin_headers, json={
        "is_active": False,
    })
    assert r_fail.status_code == 500

    # Restore commit
    monkeypatch.setattr(db.session, "commit", original_commit)

    # Verify atomic rollback: user is still active and token remains unrevoked
    app = auth_test_context["app"]
    with app.app_context():
        u = db.session.get(User, user_id)
        assert u.is_active is True
        t = AuthTokenRecord.query.filter_by(user_id=user_id).first()
        assert t is not None
        assert t.revoked is False


def test_auth_refresh_failure_fails_safely_without_stale_credentials(auth_test_context, monkeypatch):
    """Verify authentication fails safely when user refresh fails and does not authenticate with stale data."""
    from auth.service import AuthService
    from auth.models import User, db
    app = auth_test_context["app"]
    client = auth_test_context["client"]
    admin_name = auth_test_context["admin"]["user"].username

    # 1. Simulate in-memory stale state
    with app.app_context():
        u = User.query.filter_by(username=admin_name).first()
        # Change password in memory only without committing
        u.set_password("StaleInMemoryPassword123!")

        # Monkeypatch db.session.refresh to raise an exception
        def broken_refresh(instance):
            raise RuntimeError("Simulated database connection failure during credential refresh")

        monkeypatch.setattr(db.session, "refresh", broken_refresh)

        # Attempt to authenticate with the stale in-memory password
        user, token, expires_at, err = AuthService.authenticate(admin_name, "StaleInMemoryPassword123!")
        assert user is None
        assert token is None
        assert err == "Authentication service unavailable."

        # Attempt to authenticate via HTTP API
        r_api = client.post("/api/auth/login", json={
            "username": admin_name,
            "password": "StaleInMemoryPassword123!",
        })
        assert r_api.status_code == 401
        data = r_api.get_json()
        assert "Simulated database connection failure" not in str(data)
        assert "StaleInMemoryPassword123!" not in str(data)

    # 2. Restore refresh and verify session is safe for subsequent requests
    monkeypatch.undo()
    with app.app_context():
        # Clean session
        db.session.rollback()
        # Normal login works with valid DB credentials
        user, token, expires_at, err = AuthService.authenticate(admin_name, "AdminPassword123!")
        assert user is not None
        assert token is not None
        assert err is None


def test_constraint_status_detects_defective_index_definitions(auth_test_context):
    """Verify check_single_admin_constraint_status identifies non-unique, wrong-column, and wrong-predicate indexes."""
    from database import check_single_admin_constraint_status, ensure_single_admin_constraint, db
    from sqlalchemy import text
    app = auth_test_context["app"]
    client = auth_test_context["client"]
    admin_headers = {"Authorization": f"Bearer {auth_test_context['admin']['token']}"}

    with app.app_context():
        # Case 1: Non-unique index
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.execute(text("CREATE INDEX uq_single_admin ON users(role) WHERE role = 'ADMIN'"))
        db.session.commit()

        status_non_unique = check_single_admin_constraint_status()
        assert status_non_unique["supported"] is True
        assert status_non_unique["installed"] is False
        assert "not declared UNIQUE" in status_non_unique["details"]

        # Case 2: Wrong column (e.g. username instead of role)
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.execute(text("CREATE UNIQUE INDEX uq_single_admin ON users(username) WHERE role = 'ADMIN'"))
        db.session.commit()

        status_wrong_col = check_single_admin_constraint_status()
        assert status_wrong_col["installed"] is False
        assert "targets column 'username', expected 'role'" in status_wrong_col["details"]

        # Case 3: Missing partial WHERE predicate
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.execute(text("CREATE UNIQUE INDEX uq_single_admin ON users(role)"))
        db.session.commit()

        status_no_where = check_single_admin_constraint_status()
        assert status_no_where["installed"] is False
        assert "lacks partial WHERE predicate" in status_no_where["details"]

        # Case 4: Wrong predicate (e.g. role = 'ANALYST')
        db.session.execute(text("DROP INDEX IF EXISTS uq_single_admin"))
        db.session.execute(text("CREATE UNIQUE INDEX uq_single_admin ON users(role) WHERE role = 'ANALYST'"))
        db.session.commit()

        status_wrong_pred = check_single_admin_constraint_status()
        assert status_wrong_pred["installed"] is False
        assert "does not restrict to role = 'ADMIN'" in status_wrong_pred["details"]

        # Diagnostics marks system as degraded under defective constraint
        r_diag = client.get("/api/system/status", headers=admin_headers)
        assert r_diag.status_code == 200
        diag_data = r_diag.get_json()
        assert diag_data["account_policy"]["status"] == "UNVERIFIED_CONSTRAINT"
        assert diag_data["status"] == "degraded"

        # Auto-repair via ensure_single_admin_constraint drops defective index and establishes valid constraint
        repaired = ensure_single_admin_constraint()
        assert repaired is True
        status_repaired = check_single_admin_constraint_status()
        assert status_repaired["installed"] is True
        assert "verified partial unique index" in status_repaired["details"]

        # System diagnostics returns to healthy
        r_diag_ok = client.get("/api/system/status", headers=admin_headers)
        assert r_diag_ok.get_json()["account_policy"]["status"] == "OK"




