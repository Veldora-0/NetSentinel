"""Tests for Phase 13 - Authentication, Tokens, and User Management.

Verifies:
- Password validation and hashing (scrypt via werkzeug).
- Token generation, hashing (SHA-256), verification, expiration, and revocation.
- Authentication service (login, logout, change password).
- Auth API endpoints (/api/auth/login, /api/auth/logout, /api/auth/me, /api/auth/change-password).
- User management API endpoints (/api/auth/users).
- Admin bootstrap mechanics and CLI tool.
"""

import time
import pytest
from flask import Flask

from config import Config
from database import db, init_db
from auth.models import User, AuthTokenRecord
from auth.roles import Role, Permission, has_permission, get_role_permissions
from auth.service import AuthService
from auth.bootstrap import bootstrap_admin_if_needed


@pytest.fixture
def auth_app():
    """Create an isolated Flask test application with auth enabled and in-memory SQLite."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["AUTH_ENFORCE_IN_TESTS"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SECRET_KEY"] = "test-secret-key"

    init_db(app)

    # Register auth blueprint
    from auth.routes import auth_bp
    app.register_blueprint(auth_bp)

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def auth_client(auth_app):
    return auth_app.test_client()


# ==============================================================================
# Model & Password Hashing Unit Tests
# ==============================================================================

def test_user_password_hashing(auth_app):
    """Verify that passwords are securely hashed and plaintexts never stored."""
    with auth_app.app_context():
        user = User(username="secops_alice", role=Role.ANALYST)
        user.set_password("CorrectHorseBatteryStaple123!")
        db.session.add(user)
        db.session.commit()

        # Password hash must not equal plaintext
        assert user.password_hash != "CorrectHorseBatteryStaple123!"
        assert "scrypt:" in user.password_hash or "pbkdf2:" in user.password_hash

        # Verification
        assert user.check_password("CorrectHorseBatteryStaple123!") is True
        assert user.check_password("WrongPassword123!") is False
        assert user.check_password("") is False


def test_user_to_dict_redacts_password(auth_app):
    """Verify to_dict does not contain password_hash or secret tokens."""
    with auth_app.app_context():
        user = User(username="bob_viewer", role=Role.VIEWER)
        user.set_password("AStrongPassword999#")
        d = user.to_dict()

        assert "password" not in d
        assert "password_hash" not in d
        assert d["username"] == "bob_viewer"
        assert d["role"] == Role.VIEWER
        assert d["is_active"] is True
        assert "permissions" in d
        assert Permission.READ_SECURITY in d["permissions"]
        assert Permission.MANAGE_FIREWALL not in d["permissions"]


def test_auth_token_record_validity(auth_app):
    """Verify AuthTokenRecord expiration and revocation checks."""
    with auth_app.app_context():
        user = User(username="charlie", role=Role.ADMIN)
        user.set_password("SecurePass123!")
        db.session.add(user)
        db.session.commit()

        now = time.time()
        # Valid token
        tok_valid = AuthTokenRecord(
            token_hash="hash1",
            user_id=user.id,
            expires_at=now + 3600,
        )
        assert tok_valid.is_valid() is True

        # Expired token
        tok_expired = AuthTokenRecord(
            token_hash="hash2",
            user_id=user.id,
            expires_at=now - 10,
        )
        assert tok_expired.is_valid() is False

        # Revoked token
        tok_revoked = AuthTokenRecord(
            token_hash="hash3",
            user_id=user.id,
            expires_at=now + 3600,
            revoked=True,
        )
        assert tok_revoked.is_valid() is False


# ==============================================================================
# AuthService Unit Tests
# ==============================================================================

def test_auth_service_user_validation():
    """Verify username and password validation rules."""
    ok, err = AuthService.validate_username("valid_user1")
    assert ok is True and err is None

    ok, err = AuthService.validate_username("ab")  # Too short
    assert ok is False and "3" in err

    ok, err = AuthService.validate_username("user!name")  # Invalid characters
    assert ok is False

    ok, err = AuthService.validate_password("short")  # < 8 chars
    assert ok is False and "8" in err

    ok, err = AuthService.validate_password("goodpassword123")
    assert ok is True and err is None


def test_auth_service_create_and_authenticate(auth_app):
    """Verify user creation and successful authentication."""
    with auth_app.app_context():
        user, err = AuthService.create_user(
            username="analyst_dan",
            password="StrongPassword123!",
            role=Role.ANALYST,
        )
        assert err is None
        assert user is not None
        assert user.username == "analyst_dan"

        # Duplicate username should fail
        dup_user, dup_err = AuthService.create_user(
            username="analyst_dan",
            password="StrongPassword123!",
        )
        assert dup_user is None
        assert "already exists" in dup_err

        # Authenticate with right credentials
        auth_user, tok, exp, a_err = AuthService.authenticate("analyst_dan", "StrongPassword123!")
        assert a_err is None
        assert auth_user is not None
        assert tok is not None
        assert auth_user.id == user.id

        # Verify raw token against DB
        v_user = AuthService.verify_token(tok)
        assert v_user is not None
        assert v_user.username == "analyst_dan"

        # Wrong credentials
        fail_user, fail_tok, _, _ = AuthService.authenticate("analyst_dan", "IncorrectPass!")
        assert fail_user is None
        assert fail_tok is None

        # Non-existent user
        ghost_user, ghost_tok, _, _ = AuthService.authenticate("ghost_user", "IncorrectPass!")
        assert ghost_user is None
        assert ghost_tok is None


def test_auth_service_token_revocation(auth_app):
    """Verify token revocation on logout."""
    with auth_app.app_context():
        AuthService.create_user("eve_admin", "AdminPass123!", Role.ADMIN)
        _, raw_token, _, _ = AuthService.authenticate("eve_admin", "AdminPass123!")

        # Valid before revocation
        v_user = AuthService.verify_token(raw_token)
        assert v_user is not None

        # Revoke
        rev_ok = AuthService.revoke_token(raw_token)
        assert rev_ok is True

        # Invalid after revocation
        v_user2 = AuthService.verify_token(raw_token)
        assert v_user2 is None


# ==============================================================================
# Auth API Endpoints Tests
# ==============================================================================

def test_api_login_success_and_logout(auth_app, auth_client):
    """Test /api/auth/login and /api/auth/logout endpoints."""
    with auth_app.app_context():
        AuthService.create_user("operator_frank", "PasswordOper123!", Role.ANALYST)

    # Login
    resp = auth_client.post("/api/auth/login", json={
        "username": "operator_frank",
        "password": "PasswordOper123!",
    })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "ok"
    assert "token" in data
    assert data["user"]["username"] == "operator_frank"
    assert data["user"]["role"] == Role.ANALYST

    token = data["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # /api/auth/me
    resp_me = auth_client.get("/api/auth/me", headers=headers)
    assert resp_me.status_code == 200
    data_me = resp_me.get_json()
    assert data_me["status"] == "ok"
    assert data_me["user"]["username"] == "operator_frank"

    # Logout
    resp_logout = auth_client.post("/api/auth/logout", headers=headers)
    assert resp_logout.status_code == 200

    # Token must now be rejected
    resp_me_after = auth_client.get("/api/auth/me", headers=headers)
    assert resp_me_after.status_code == 401


def test_api_login_failures(auth_app, auth_client):
    """Test bad credentials, missing fields, nonexistent users, and disabled users.
    
    Verifies that all credential failures produce an identical response schema and HTTP 401
    status without leaking account existence or distinguishing disabled accounts.
    """
    with auth_app.app_context():
        u, _ = AuthService.create_user("disabled_user", "ValidPass123!", Role.VIEWER)
        u.is_active = False
        db.session.commit()

    # Missing fields
    resp = auth_client.post("/api/auth/login", json={"username": "test"})
    assert resp.status_code == 400

    # 1. Nonexistent username
    resp_nonexistent = auth_client.post("/api/auth/login", json={
        "username": "definitely_nonexistent_user_999",
        "password": "AnyPassword123!",
    })
    assert resp_nonexistent.status_code == 401
    data_nonexistent = resp_nonexistent.get_json()

    # 2. Wrong password for existing user
    resp_wrong_pw = auth_client.post("/api/auth/login", json={
        "username": "disabled_user",
        "password": "WrongPassword123!",
    })
    assert resp_wrong_pw.status_code == 401
    data_wrong_pw = resp_wrong_pw.get_json()

    # 3. Disabled existing account
    resp_disabled = auth_client.post("/api/auth/login", json={
        "username": "disabled_user",
        "password": "ValidPass123!",
    })
    assert resp_disabled.status_code == 401
    data_disabled = resp_disabled.get_json()

    # Verify uniform responses: identical status_code, error type, and message
    assert data_nonexistent["message"] == "Invalid username or password."
    assert data_wrong_pw["message"] == "Invalid username or password."
    assert data_disabled["message"] == "Invalid username or password."

    assert data_nonexistent["error"] == "unauthorized"
    assert data_wrong_pw["error"] == "unauthorized"
    assert data_disabled["error"] == "unauthorized"


def test_api_change_password(auth_app, auth_client):
    """Test /api/auth/change-password endpoint."""
    with auth_app.app_context():
        AuthService.create_user("pass_user", "OldPassword123!", Role.VIEWER)

    # Login to get token
    resp = auth_client.post("/api/auth/login", json={
        "username": "pass_user",
        "password": "OldPassword123!",
    })
    token = resp.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Try changing with wrong current password
    resp_fail = auth_client.post("/api/auth/change-password", headers=headers, json={
        "current_password": "WrongOldPassword!",
        "new_password": "BrandNewPassword123!",
    })
    assert resp_fail.status_code == 400

    # Change successfully
    resp_ok = auth_client.post("/api/auth/change-password", headers=headers, json={
        "current_password": "OldPassword123!",
        "new_password": "BrandNewPassword123!",
    })
    assert resp_ok.status_code == 200

    # Old token was revoked
    resp_old_tok = auth_client.get("/api/auth/me", headers=headers)
    assert resp_old_tok.status_code == 401

    # Logging in with new password succeeds
    resp_new_login = auth_client.post("/api/auth/login", json={
        "username": "pass_user",
        "password": "BrandNewPassword123!",
    })
    assert resp_new_login.status_code == 200
    new_token = resp_new_login.get_json()["token"]
    new_headers = {"Authorization": f"Bearer {new_token}"}
    resp_new_me = auth_client.get("/api/auth/me", headers=new_headers)
    assert resp_new_me.status_code == 200


# ==============================================================================
# Admin User Management API Tests
# ==============================================================================

def test_api_user_management_lifecycle(auth_app, auth_client):
    """Test CRUD operations on users via admin."""
    with auth_app.app_context():
        AuthService.create_user("super_admin", "AdminPassword123!", Role.ADMIN)

    # Login as admin
    resp = auth_client.post("/api/auth/login", json={
        "username": "super_admin",
        "password": "AdminPassword123!",
    })
    admin_token = resp.get_json()["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create a new user
    resp_create = auth_client.post("/api/auth/users", headers=admin_headers, json={
        "username": "tier1_analyst",
        "password": "InitialPassword123!",
        "role": Role.ANALYST,
    })
    assert resp_create.status_code == 201
    created_user = resp_create.get_json()["user"]
    user_id = created_user["id"]
    assert created_user["username"] == "tier1_analyst"
    assert created_user["role"] == Role.ANALYST

    # 2. List users
    resp_list = auth_client.get("/api/auth/users", headers=admin_headers)
    assert resp_list.status_code == 200
    users = resp_list.get_json()["users"]
    assert len(users) == 2

    # 3. Update user role
    resp_patch = auth_client.patch(f"/api/auth/users/{user_id}", headers=admin_headers, json={
        "role": Role.VIEWER,
        "is_active": True,
    })
    assert resp_patch.status_code == 200
    assert resp_patch.get_json()["user"]["role"] == Role.VIEWER

    # 4. Delete user
    resp_del = auth_client.delete(f"/api/auth/users/{user_id}", headers=admin_headers)
    assert resp_del.status_code == 200

    # 5. Verify deleted
    resp_list2 = auth_client.get("/api/auth/users", headers=admin_headers)
    assert len(resp_list2.get_json()["users"]) == 1


def test_api_last_admin_protection(auth_app, auth_client):
    """Verify safeguards prevent deleting or demoting the last active administrator."""
    with auth_app.app_context():
        admin, _ = AuthService.create_user("only_admin", "AdminPassword123!", Role.ADMIN)
        admin_id = admin.id

    resp = auth_client.post("/api/auth/login", json={
        "username": "only_admin",
        "password": "AdminPassword123!",
    })
    token = resp.get_json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Cannot demote self
    resp_demote = auth_client.patch(f"/api/auth/users/{admin_id}", headers=headers, json={
        "role": Role.ANALYST,
    })
    assert resp_demote.status_code == 400
    assert "Cannot demote your own administrator account" in resp_demote.get_json()["message"]

    # Cannot disable self
    resp_disable = auth_client.patch(f"/api/auth/users/{admin_id}", headers=headers, json={
        "is_active": False,
    })
    assert resp_disable.status_code == 400
    assert "Cannot disable your own administrator account" in resp_disable.get_json()["message"]

    # Cannot delete self
    resp_del = auth_client.delete(f"/api/auth/users/{admin_id}", headers=headers)
    assert resp_del.status_code == 400
    assert "Cannot delete your own administrator account" in resp_del.get_json()["message"]

    # Now create a second admin (admin2)
    with auth_app.app_context():
        admin2, _ = AuthService.create_user("admin2", "AdminPass456!", Role.ADMIN)
        admin2_id = admin2.id

    resp2 = auth_client.post("/api/auth/login", json={
        "username": "admin2",
        "password": "AdminPass456!",
    })
    headers2 = {"Authorization": f"Bearer {resp2.get_json()['token']}"}

    # Admin2 can delete only_admin now because admin2 is still active
    resp_del_ok = auth_client.delete(f"/api/auth/users/{admin_id}", headers=headers2)
    assert resp_del_ok.status_code == 200

    # But now admin2 is the sole remaining active admin, so they cannot delete or disable themselves
    resp_del_sole = auth_client.delete(f"/api/auth/users/{admin2_id}", headers=headers2)
    assert resp_del_sole.status_code == 400


def test_admin_bootstrap(auth_app):
    """Test initial admin bootstrap functionality."""
    with auth_app.app_context():
        # First ensure no users exist
        User.query.delete()
        db.session.commit()

        # Call bootstrap without env password
        assert bootstrap_admin_if_needed(auth_app) is None

        # Set env password in config
        auth_app.config["AUTH_ADMIN_PASSWORD"] = "AutoBootstrapPass123!"
        auth_app.config["AUTH_ADMIN_USERNAME"] = "auto_admin"

        # Bootstrap should create admin
        created = bootstrap_admin_if_needed(auth_app)
        assert created is not None
        assert created.username == "auto_admin"
        assert created.role == Role.ADMIN
        assert created.check_password("AutoBootstrapPass123!") is True

        # Second run should be a no-op
        created_again = bootstrap_admin_if_needed(auth_app)
        assert created_again is None
