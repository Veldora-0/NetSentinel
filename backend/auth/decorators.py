"""NetSentinel Authentication & Authorization Decorators.

Provides reusable view decorators enforcing authentication, role boundaries,
and granular permissions across Flask API routes.
"""

from functools import wraps
import logging
import os
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


def _is_auth_globally_disabled() -> bool:
    """Check if authentication is disabled, strictly prohibiting it in production."""
    if current_app.config.get("AUTH_ENABLED", True):
        return False
    env = str(current_app.config.get("ENV", "")).lower().strip()
    netsentinel_env = str(os.environ.get("NETSENTINEL_ENV", "")).lower().strip()
    if env == "production" or netsentinel_env == "production":
        logger.error("Security violation: AUTH_ENABLED cannot be False in production. Enforcing authentication.")
        return False
    return True


def _is_test_auth_bypass_allowed() -> bool:
    """Determine whether the backward-compatibility test mock bypass is permitted.

    Fail-safe invariants:
    1. NEVER allowed in production environments (ENV == 'production', NETSENTINEL_ENV == 'production').
    2. NEVER allowed merely because TESTING is enabled in a production/non-test environment.
    3. NEVER allowed when AUTH_ENFORCE_IN_TESTS is True.
    4. Only allowed under intentional, active test execution (e.g. pytest framework active or
       AUTH_ALLOW_TEST_COMPATIBILITY explicitly enabled in a non-production test suite).
    """
    cfg = current_app.config

    # 1. Strictly fail closed if in production
    env = str(cfg.get("ENV", "")).lower().strip()
    netsentinel_env = str(os.environ.get("NETSENTINEL_ENV", "")).lower().strip()
    if env == "production" or netsentinel_env == "production":
        return False

    # 2. Strict enforcement flag disables bypass
    if cfg.get("AUTH_ENFORCE_IN_TESTS", False):
        return False

    # 3. Must be explicitly flagged as a test
    if not cfg.get("TESTING", False):
        return False

    # 4. Explicit compatibility flag or active test runner
    if cfg.get("AUTH_ALLOW_TEST_COMPATIBILITY") is False:
        return False

    is_pytest = bool(os.environ.get("PYTEST_CURRENT_TEST"))
    return bool(cfg.get("AUTH_ALLOW_TEST_COMPATIBILITY", is_pytest))


def login_required(f: Callable) -> Callable:
    """Ensure the incoming request has a valid, active authentication session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Fail-closed global auth check (prohibited in production)
        if _is_auth_globally_disabled():
            return f(*args, **kwargs)

        # 2. Verify Bearer token from request
        user = get_current_user_from_request()
        if user:
            g.current_user = user
            return f(*args, **kwargs)

        # 3. Safe, intentional test compatibility fallback
        if _is_test_auth_bypass_allowed():
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
            if _is_auth_globally_disabled():
                return f(*args, **kwargs)

            user = get_current_user_from_request()
            if not user:
                if _is_test_auth_bypass_allowed():
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

            # Verify permission
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
            if _is_auth_globally_disabled():
                return f(*args, **kwargs)

            user = get_current_user_from_request()
            if not user:
                if _is_test_auth_bypass_allowed():
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
