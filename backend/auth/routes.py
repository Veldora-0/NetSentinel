"""NetSentinel Authentication & User Management REST Routes.

Defines API endpoints for authentication (login, logout, session verification),
self-service password changes, and administrator user provisioning.
"""

import logging
import time
from flask import Blueprint, jsonify, request, g

from database import db
from auth.models import User, AuthTokenRecord
from auth.roles import Role, Permission, ALL_ROLES
from auth.service import AuthService
from auth.decorators import (
    login_required,
    permission_required,
    get_raw_token_from_request,
)

logger = logging.getLogger("netsentinel.auth.routes")

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate credentials and issue a bearer token session."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "error": "bad_request",
            "message": "Both username and password are required.",
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    user, token, expires_at, err = AuthService.authenticate(
        username=username,
        password=password,
        client_ip=client_ip,
    )

    if err or not user:
        return jsonify({
            "error": "unauthorized",
            "message": "Invalid username or password.",
            "status_code": 401,
            "request_id": getattr(g, "request_id", "-"),
        }), 401

    return jsonify({
        "status": "ok",
        "message": "Authentication successful",
        "token": token,
        "expires_at": expires_at,
        "user": user.to_dict(),
        "request_id": getattr(g, "request_id", "-"),
    }), 200


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """Revoke the current authentication token."""
    raw_token = get_raw_token_from_request()
    if raw_token:
        AuthService.revoke_token(raw_token)
    username = getattr(getattr(g, "current_user", None), "username", "unknown")
    logger.info("User '%s' logged out", username)
    return jsonify({
        "status": "ok",
        "message": "Logged out successfully",
        "request_id": getattr(g, "request_id", "-"),
    }), 200


@auth_bp.route("/me", methods=["GET"])
@login_required
def get_current_user_profile():
    """Retrieve profile and permissions for the currently authenticated user."""
    user = getattr(g, "current_user", None)
    if not user:
        return jsonify({
            "error": "unauthorized",
            "message": "Not authenticated",
            "status_code": 401,
            "request_id": getattr(g, "request_id", "-"),
        }), 401

    from auth.roles import get_role_permissions
    user_dict = user.to_dict()
    user_dict["permissions"] = sorted(list(get_role_permissions(user.role)))

    return jsonify({
        "status": "ok",
        "user": user_dict,
        "request_id": getattr(g, "request_id", "-"),
    }), 200


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    """Change password for the currently authenticated user."""
    user = getattr(g, "current_user", None)
    if not user:
        return jsonify({
            "error": "unauthorized",
            "message": "Not authenticated",
            "status_code": 401,
            "request_id": getattr(g, "request_id", "-"),
        }), 401

    data = request.get_json(silent=True) or {}
    curr_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")

    if not curr_pw or not new_pw:
        return jsonify({
            "error": "bad_request",
            "message": "Both current_password and new_password are required.",
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    from flask import current_app
    min_len = current_app.config.get("AUTH_PASSWORD_MIN_LENGTH", 8)

    success, err = AuthService.change_password(
        user=user,
        current_password=curr_pw,
        new_password=new_pw,
        min_password_length=min_len,
    )

    if not success:
        return jsonify({
            "error": "bad_request",
            "message": err or "Failed to change password.",
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    return jsonify({
        "status": "ok",
        "message": "Password changed successfully.",
        "request_id": getattr(g, "request_id", "-"),
    }), 200


@auth_bp.route("/users", methods=["GET"])
@permission_required(Permission.MANAGE_USERS)
def list_users():
    """Administrator endpoint: list all registered users."""
    users = User.query.order_by(User.id).all()
    admin_count = sum(1 for u in users if u.role == Role.ADMIN)

    response_payload = {
        "status": "ok",
        "count": len(users),
        "admin_count": admin_count,
        "users": [u.to_dict() for u in users],
        "request_id": getattr(g, "request_id", "-"),
    }
    if admin_count > 1:
        response_payload["policy_warning"] = (
            f"Multiple administrator accounts ({admin_count}) detected. "
            "NetSentinel enforces a single administrator policy. Run "
            "'python backend/bootstrap.py --resolve-multiple-admins' to resolve."
        )
    return jsonify(response_payload), 200


@auth_bp.route("/users", methods=["POST"])
@permission_required(Permission.MANAGE_USERS)
def create_user():
    """Administrator endpoint: create a new user (Analyst or Viewer)."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    role = data.get("role", Role.ANALYST)
    is_active = data.get("is_active", True)

    if not username or not password:
        return jsonify({
            "error": "bad_request",
            "message": "Both username and password are required.",
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    # NetSentinel single-administrator policy: never allow creating another ADMIN via API
    req_role = str(role).upper().strip()
    if req_role == Role.ADMIN:
        return jsonify({
            "error": "bad_request",
            "message": "Cannot create additional administrator accounts. NetSentinel enforces a single administrator policy.",
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    from flask import current_app
    min_len = current_app.config.get("AUTH_PASSWORD_MIN_LENGTH", 8)

    user, err = AuthService.create_user(
        username=username,
        password=password,
        role=req_role,
        is_active=is_active,
        min_password_length=min_len,
    )

    if err:
        code = 409 if "already exists" in err.lower() else 400
        return jsonify({
            "error": "conflict" if code == 409 else "bad_request",
            "message": err,
            "status_code": code,
            "request_id": getattr(g, "request_id", "-"),
        }), code

    admin_user = getattr(g, "current_user", None)
    admin_name = getattr(admin_user, "username", "system")
    logger.info("Admin '%s' created user '%s' with role '%s'", admin_name, user.username, user.role)

    return jsonify({
        "status": "ok",
        "message": "User created successfully",
        "user": user.to_dict(),
        "request_id": getattr(g, "request_id", "-"),
    }), 201


@auth_bp.route("/users/<int:user_id>", methods=["PATCH", "PUT"])
@permission_required(Permission.MANAGE_USERS)
def update_user(user_id: int):
    """Administrator endpoint: update user role, status, or reset password."""
    target_user = db.session.get(User, user_id)
    if not target_user:
        return jsonify({
            "error": "not_found",
            "message": f"User with ID {user_id} not found.",
            "status_code": 404,
            "request_id": getattr(g, "request_id", "-"),
        }), 404

    data = request.get_json(silent=True) or {}
    admin_user = getattr(g, "current_user", None)
    admin_name = getattr(admin_user, "username", "admin")

    with AuthService._user_mutation_lock:
        # Guardrails for the administrator account: cannot demote or disable
        if target_user.role == Role.ADMIN:
            is_self = admin_user and target_user.id == admin_user.id
            if "role" in data and str(data["role"]).upper().strip() != Role.ADMIN:
                msg = "Cannot demote your own administrator account." if is_self else "Cannot demote the sole administrator account."
                return jsonify({
                    "error": "bad_request",
                    "message": msg,
                    "status_code": 400,
                    "request_id": getattr(g, "request_id", "-"),
                }), 400
            if "is_active" in data and not data["is_active"]:
                msg = "Cannot disable your own administrator account." if is_self else "Cannot disable the sole administrator account."
                return jsonify({
                    "error": "bad_request",
                    "message": msg,
                    "status_code": 400,
                    "request_id": getattr(g, "request_id", "-"),
                }), 400

        # Guardrails for non-admin accounts: cannot promote to ADMIN
        if "role" in data:
            new_role = str(data["role"]).upper().strip()
            if new_role == Role.ADMIN and target_user.role != Role.ADMIN:
                return jsonify({
                    "error": "bad_request",
                    "message": "Cannot promote accounts to administrator. NetSentinel enforces a single administrator policy.",
                    "status_code": 400,
                    "request_id": getattr(g, "request_id", "-"),
                }), 400
            if new_role not in ALL_ROLES:
                return jsonify({
                    "error": "bad_request",
                    "message": f"Invalid role '{new_role}'. Allowed: {', '.join(ALL_ROLES)}",
                    "status_code": 400,
                    "request_id": getattr(g, "request_id", "-"),
                }), 400
            if new_role != target_user.role:
                target_user.role = new_role
                # Revoke active sessions on role change so new permissions require new session
                AuthTokenRecord.query.filter_by(user_id=target_user.id, revoked=False).update(
                    {"revoked": True, "revoked_at": time.time()}
                )

        # Active status update
        if "is_active" in data:
            new_active = bool(data["is_active"])
            target_user.is_active = new_active
            if not new_active:
                # Deactivating an account immediately revokes all active session tokens
                AuthTokenRecord.query.filter_by(user_id=target_user.id, revoked=False).update(
                    {"revoked": True, "revoked_at": time.time()}
                )

        # Password reset
        if "password" in data:
            from flask import current_app
            min_len = current_app.config.get("AUTH_PASSWORD_MIN_LENGTH", 8)
            success, err = AuthService.admin_reset_password(
                user=target_user,
                new_password=data["password"],
                admin_username=admin_name,
                min_password_length=min_len,
            )
            if not success:
                return jsonify({
                    "error": "bad_request",
                    "message": err or "Failed to reset password.",
                    "status_code": 400,
                    "request_id": getattr(g, "request_id", "-"),
                }), 400

        try:
            db.session.commit()
            logger.info("Admin '%s' updated user id %d ('%s')", admin_name, target_user.id, target_user.username)
            return jsonify({
                "status": "ok",
                "message": "User updated successfully",
                "user": target_user.to_dict(),
                "request_id": getattr(g, "request_id", "-"),
            }), 200
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to update user %d: %s", target_user.id, ex)
            return jsonify({
                "error": "internal_error",
                "message": "Database error updating user.",
                "status_code": 500,
                "request_id": getattr(g, "request_id", "-"),
            }), 500


@auth_bp.route("/users/<int:user_id>", methods=["DELETE"])
@permission_required(Permission.MANAGE_USERS)
def delete_user(user_id: int):
    """Administrator endpoint: delete a user."""
    target_user = db.session.get(User, user_id)
    if not target_user:
        return jsonify({
            "error": "not_found",
            "message": f"User with ID {user_id} not found.",
            "status_code": 404,
            "request_id": getattr(g, "request_id", "-"),
        }), 404

    admin_user = getattr(g, "current_user", None)
    admin_name = getattr(admin_user, "username", "admin")

    # Enforce policy: cannot delete the administrator account
    if target_user.role == Role.ADMIN:
        is_self = admin_user and target_user.id == admin_user.id
        msg = "Cannot delete your own administrator account." if is_self else "Cannot delete the sole administrator account."
        return jsonify({
            "error": "bad_request",
            "message": msg,
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    try:
        username = target_user.username
        db.session.delete(target_user)
        db.session.commit()
        logger.info("Admin '%s' deleted user id %d ('%s')", admin_name, user_id, username)
        return jsonify({
            "status": "ok",
            "message": f"User '{username}' deleted successfully.",
            "request_id": getattr(g, "request_id", "-"),
        }), 200
    except Exception as ex:
        db.session.rollback()
        logger.error("Failed to delete user %d: %s", user_id, ex)
        return jsonify({
            "error": "internal_error",
            "message": "Database error deleting user.",
            "status_code": 500,
            "request_id": getattr(g, "request_id", "-"),
        }), 500
