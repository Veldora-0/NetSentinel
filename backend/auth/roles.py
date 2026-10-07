"""NetSentinel Role-Based Access Control (RBAC) Definitions.

Defines role identifiers, discrete permission scopes, and role-to-permission
hierarchy mappings for the NetSentinel management plane.
"""

from typing import Set


class Permission:
    """Discrete granular permissions within the NetSentinel management plane."""
    READ_SECURITY = "read:security"           # View dashboards, alerts, events, metrics, logs, reports
    MANAGE_INCIDENTS = "manage:incidents"     # Acknowledge, resolve, close, reopen correlated incidents
    QUERY_THREAT_INTEL = "query:threat_intel" # On-demand external public IP reputation lookups
    MANAGE_FIREWALL = "manage:firewall"       # Insert/remove manual firewall drop rules
    MANAGE_FIM = "manage:fim"                 # Trigger cryptographic file rebaselining
    MANAGE_USERS = "manage:users"             # Create, update, toggle, reset passwords, delete users
    SYSTEM_ADMIN = "system:admin"             # Operational runtime controls & diagnostics


class Role:
    """Standard user roles for NetSentinel operators."""
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


# Granular permissions assigned to each role
ROLE_PERMISSIONS = {
    Role.VIEWER: {
        Permission.READ_SECURITY,
    },
    Role.ANALYST: {
        Permission.READ_SECURITY,
        Permission.MANAGE_INCIDENTS,
        Permission.QUERY_THREAT_INTEL,
    },
    Role.ADMIN: {
        Permission.READ_SECURITY,
        Permission.MANAGE_INCIDENTS,
        Permission.QUERY_THREAT_INTEL,
        Permission.MANAGE_FIREWALL,
        Permission.MANAGE_FIM,
        Permission.MANAGE_USERS,
        Permission.SYSTEM_ADMIN,
    },
}

ALL_ROLES = (Role.ADMIN, Role.ANALYST, Role.VIEWER)


def get_role_permissions(role: str) -> Set[str]:
    """Retrieve the set of permissions associated with a given role."""
    return ROLE_PERMISSIONS.get(str(role).upper().strip(), set())


def has_permission(role: str, permission: str) -> bool:
    """Check whether a given role possesses a specific permission."""
    perms = get_role_permissions(role)
    return permission in perms
