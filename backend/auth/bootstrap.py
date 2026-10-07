"""NetSentinel Initial Administrator Bootstrap Module.

Safely initializes the initial administrator account without hardcoding credentials in source code.
Supports configuration/environment variables or explicit CLI invocation.
"""

import logging
from typing import Optional

from auth.models import User
from auth.roles import Role
from auth.service import AuthService

logger = logging.getLogger("netsentinel.auth.bootstrap")


def bootstrap_admin_if_needed(app) -> Optional[User]:
    """Inspect the database and bootstrap an initial administrator if none exists.
    
    Reads credentials from application configuration (NETSENTINEL_ADMIN_PASSWORD).
    Does NOT log or leak the password string.
    """
    with app.app_context():
        try:
            admin_count = User.query.filter_by(role=Role.ADMIN).count()
            if admin_count > 0:
                return None

            admin_password = app.config.get("AUTH_ADMIN_PASSWORD", "").strip()
            admin_username = app.config.get("AUTH_ADMIN_USERNAME", "admin").strip() or "admin"
            min_length = app.config.get("AUTH_PASSWORD_MIN_LENGTH", 8)

            if not admin_password:
                logger.info(
                    "No administrator account found in database. Configure NETSENTINEL_ADMIN_PASSWORD or run 'python backend/bootstrap.py' to initialize."
                )
                return None

            user, err = AuthService.create_user(
                username=admin_username,
                password=admin_password,
                role=Role.ADMIN,
                is_active=True,
                min_password_length=min_length,
            )

            if err:
                logger.warning("Failed to auto-bootstrap administrator account '%s': %s", admin_username, err)
                return None

            logger.info("Successfully bootstrapped initial administrator account: username='%s'", admin_username)
            return user
        except Exception as ex:
            logger.error("Error during administrator bootstrap check: %s", ex)
            return None
