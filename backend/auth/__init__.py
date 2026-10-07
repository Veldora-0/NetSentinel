"""NetSentinel Authentication & Authorization (RBAC) Package.

Exports core user models, roles, permissions, decorators, and authentication service.
"""

from auth.models import User, AuthTokenRecord
from auth.roles import Role, Permission, ALL_ROLES, has_permission, get_role_permissions
from auth.service import AuthService
from auth.decorators import (
    login_required,
    permission_required,
    role_required,
    admin_required,
    analyst_required,
    get_current_user_from_request,
    get_raw_token_from_request,
)
from auth.bootstrap import bootstrap_admin_if_needed

__all__ = [
    "User",
    "AuthTokenRecord",
    "Role",
    "Permission",
    "ALL_ROLES",
    "has_permission",
    "get_role_permissions",
    "AuthService",
    "login_required",
    "permission_required",
    "role_required",
    "admin_required",
    "analyst_required",
    "get_current_user_from_request",
    "get_raw_token_from_request",
    "bootstrap_admin_if_needed",
]
