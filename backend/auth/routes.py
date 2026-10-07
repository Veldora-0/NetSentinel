"""NetSentinel Authentication & User Management REST Routes.

Defines API endpoints for authentication (login, logout, session verification),
self-service password changes, and administrator user provisioning.
"""

import logging
from flask import Blueprint, jsonify, request, g

from database import db
from auth.models import User
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
        status_code = 403 if (err and "disabled" in err.lower()) else 401
        err_type = "forbidden" if status_code == 403 else "unauthorized"
        return jsonify({
            "error": err_type,
            "message": err or "Invalid username or password.",
            "status_code": status_code,
            "request_id": getattr(g, "request_id", "-"),
        }), status_code

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
    return jsonify({
        "status": "ok",
        "count": len(users),
        "users": [u.to_dict() for u in users],
        "request_id": getattr(g, "request_id", "-"),
    }), 200


@auth_bp.route("/users", methods=["POST"])
@permission_required(Permission.MANAGE_USERS)
def create_user():
    """Administrator endpoint: create a new user."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")
    role = data.get("role", Role.VIEWER)
    is_active = data.get("is_active", True)

    if not username or not password:
        return jsonify({
            "error": "bad_request",
            "message": "Both username and password are required.",
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    from flask import current_app
    min_len = current_app.config.get("AUTH_PASSWORD_MIN_LENGTH", 8)

    user, err = AuthService.create_user(
        username=username,
        password=password,
        role=role,
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

    # Guardrails for self-modification
    if admin_user and target_user.id == admin_user.id:
        if "is_active" in data and not data["is_active"]:
            return jsonify({
                "error": "bad_request",
                "message": "Cannot disable your own administrator account.",
                "status_code": 400,
                "request_id": getattr(g, "request_id", "-"),
            }), 400
        if "role" in data and str(data["role"]).upper() != Role.ADMIN:
            return jsonify({
                "error": "bad_request",
                "message": "Cannot demote your own administrator account.",
                "status_code": 400,
                "request_id": getattr(g, "request_id", "-"),
            }), 400

    # Guardrails for last active administrator
    if target_user.role == Role.ADMIN:
        will_demote = "role" in data and str(data["role"]).upper() != Role.ADMIN
        will_disable = "is_active" in data and not data["is_active"]
        if will_demote or will_disable:
            other_active_admins = User.query.filter(
                User.role == Role.ADMIN,
                User.is_active == True,
                User.id != target_user.id,
            ).count()
            if other_active_admins == 0:
                action = "demote" if will_demote else "disable"
                return jsonify({
                    "error": "bad_request",
                    "message": f"Cannot {action} the last active administrator account.",
                    "status_code": 400,
                    "request_id": getattr(g, "request_id", "-"),
                }), 400

    # Role update
    if "role" in data:
        new_role = str(data["role"]).upper().strip()
        if new_role not in ALL_ROLES:
            return jsonify({
                "error": "bad_request",
                "message": f"Invalid role '{new_role}'. Allowed: {', '.join(ALL_ROLES)}",
                "status_code": 400,
                "request_id": getattr(g, "request_id", "-"),
            }), 400
        target_user.role = new_role

    # Active status update
    if "is_active" in data:
        target_user.is_active = bool(data["is_active"])

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
    if admin_user and target_user.id == admin_user.id:
        return jsonify({
            "error": "bad_request",
            "message": "Cannot delete your own administrator account.",
            "status_code": 400,
            "request_id": getattr(g, "request_id", "-"),
        }), 400

    if target_user.role == Role.ADMIN:
        remaining_admins = User.query.filter(
            User.role == Role.ADMIN,
            User.is_active == True,
            User.id != target_user.id,
        ).count()
        if remaining_admins == 0:
            return jsonify({
                "error": "bad_request",
                "message": "Cannot delete the last active administrator account.",
                "status_code": 400,
                "request_id": getattr(g, "request_id", "-"),
            }), 400

    try:
        username = target_user.username
        db.session.delete(target_user)
        db.session.commit()
        admin_name = getattr(admin_user, "username", "admin")
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
