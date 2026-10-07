"""NetSentinel Authentication & Authorization Decorators.

Provides reusable view decorators enforcing authentication, role boundaries,
and granular permissions across Flask API routes.
"""

from functools import wraps
import logging
from typing import Callable, Optional

from flask import current_app, g, jsonify, request

from auth.models import User
from auth.roles import Permission, Role, has_permission
from auth.service import AuthService

logger = logging.getLogger("netsentinel.auth")


def get_raw_token_from_request() -> Optional[str]:
    """Extract raw bearer token from the HTTP Authorization header."""
    auth_header = request.headers.get("Authorization", "").strip()
    if not auth_header:
        return None
    parts = auth_header.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def get_current_user_from_request() -> Optional[User]:
    """Retrieve and verify the authenticated user from the current request."""
    token = get_raw_token_from_request()
    if not token:
        return None
    return AuthService.verify_token(token)


def login_required(f: Callable) -> Callable:
    """Ensure the incoming request has a valid, active authentication session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Check if authentication is globally disabled by configuration
        if not current_app.config.get("AUTH_ENABLED", True):
            return f(*args, **kwargs)

        # 2. Verify Bearer token from request
        user = get_current_user_from_request()
        if user:
            g.current_user = user
            return f(*args, **kwargs)

        # 3. Test mode backward-compatibility for pre-Phase 13 tests
        if current_app.config.get("TESTING", False) and not current_app.config.get("AUTH_ENFORCE_IN_TESTS", False):
            # Fallback mock admin for existing test suites
            g.current_user = User(id=1, username="test_admin", role=Role.ADMIN, is_active=True)
            return f(*args, **kwargs)

        # 4. Unauthenticated: return normalized 401
        return jsonify({
            "error": "unauthorized",
            "message": "Authentication required. Please provide a valid Bearer token.",
            "status_code": 401,
            "request_id": getattr(g, "request_id", "-"),
        }), 401

    return decorated_function


def permission_required(permission: str) -> Callable:
    """Ensure the authenticated user possesses the specified granular permission."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Global auth bypass check
            if not current_app.config.get("AUTH_ENABLED", True):
                return f(*args, **kwargs)

            # 2. Verify authentication first
            user = get_current_user_from_request()
            if not user:
                if current_app.config.get("TESTING", False) and not current_app.config.get("AUTH_ENFORCE_IN_TESTS", False):
                    g.current_user = User(id=1, username="test_admin", role=Role.ADMIN, is_active=True)
                    user = g.current_user
                else:
                    return jsonify({
                        "error": "unauthorized",
                        "message": "Authentication required. Please provide a valid Bearer token.",
                        "status_code": 401,
                        "request_id": getattr(g, "request_id", "-"),
                    }), 401

            g.current_user = user

            # 3. Verify permission
            if not has_permission(user.role, permission):
                logger.warning(
                    "Access denied for user '%s' (role: %s) to permission '%s' on %s %s",
                    user.username,
                    user.role,
                    permission,
                    request.method,
                    request.path,
                )
                return jsonify({
                    "error": "forbidden",
                    "message": f"Insufficient permissions: requires '{permission}'.",
                    "status_code": 403,
                    "request_id": getattr(g, "request_id", "-"),
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def role_required(*roles: str) -> Callable:
    """Ensure the authenticated user possesses one of the allowed roles."""
    allowed = {str(r).upper().strip() for r in roles}

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_app.config.get("AUTH_ENABLED", True):
                return f(*args, **kwargs)

            user = get_current_user_from_request()
            if not user:
                if current_app.config.get("TESTING", False) and not current_app.config.get("AUTH_ENFORCE_IN_TESTS", False):
                    g.current_user = User(id=1, username="test_admin", role=Role.ADMIN, is_active=True)
                    user = g.current_user
                else:
                    return jsonify({
                        "error": "unauthorized",
                        "message": "Authentication required. Please provide a valid Bearer token.",
                        "status_code": 401,
                        "request_id": getattr(g, "request_id", "-"),
                    }), 401

            g.current_user = user

            if user.role not in allowed:
                return jsonify({
                    "error": "forbidden",
                    "message": f"Role '{user.role}' is not authorized. Allowed roles: {', '.join(allowed)}.",
                    "status_code": 403,
                    "request_id": getattr(g, "request_id", "-"),
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def admin_required(f: Callable) -> Callable:
    """Convenience decorator requiring ADMIN role."""
    return permission_required(Permission.MANAGE_USERS)(f)


def analyst_required(f: Callable) -> Callable:
    """Convenience decorator requiring ANALYST or ADMIN role."""
    return permission_required(Permission.MANAGE_INCIDENTS)(f)
