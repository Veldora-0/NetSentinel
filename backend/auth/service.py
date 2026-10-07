"""NetSentinel Authentication & User Management Service.

Provides core business logic for user credential validation, secure password hashing,
authentication verification, token issuance, session revocation, and RBAC operations.
"""

import hashlib
import logging
import re
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from database import db
from auth.models import AuthTokenRecord, User
from auth.roles import ALL_ROLES, Role

logger = logging.getLogger("netsentinel.auth")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{3,32}$")


class AuthService:
    """Authentication and User Lifecycle Management Service."""

    DEFAULT_MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    DEFAULT_TOKEN_EXPIRY_SECONDS = 86400.0  # 24 hours

    @classmethod
    def validate_username(cls, username: Any) -> Tuple[bool, Optional[str]]:
        """Validate candidate username formatting."""
        if not username or not isinstance(username, str):
            return False, "Username must be a non-empty string."
        clean = username.strip()
        if not USERNAME_REGEX.match(clean):
            return False, "Username must be 3-32 characters long and contain only letters, numbers, hyphens, underscores, or periods."
        return True, None

    @classmethod
    def validate_password(
        cls, password: Any, min_length: Optional[int] = None
    ) -> Tuple[bool, Optional[str]]:
        """Validate candidate password compliance against security policy.
        
        Never echoes or discloses password content in validation errors.
        """
        min_len = min_length if min_length is not None else cls.DEFAULT_MIN_PASSWORD_LENGTH
        if not password or not isinstance(password, str):
            return False, f"Password must be at least {min_len} characters long."
        if len(password) < min_len:
            return False, f"Password must be at least {min_len} characters long."
        if len(password) > cls.MAX_PASSWORD_LENGTH:
            return False, f"Password cannot exceed {cls.MAX_PASSWORD_LENGTH} characters."
        if not password.strip():
            return False, "Password cannot be whitespace only."
        return True, None

    @classmethod
    def hash_token(cls, raw_token: str) -> str:
        """Compute deterministic SHA-256 digest of raw token for storage."""
        return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    @classmethod
    def create_user(
        cls,
        username: str,
        password: str,
        role: str = Role.VIEWER,
        is_active: bool = True,
        min_password_length: Optional[int] = None,
    ) -> Tuple[Optional[User], Optional[str]]:
        """Create a new user with hashed credentials."""
        u_valid, u_err = cls.validate_username(username)
        if not u_valid:
            return None, u_err

        p_valid, p_err = cls.validate_password(password, min_length=min_password_length)
        if not p_valid:
            return None, p_err

        normalized_role = str(role).upper().strip()
        if normalized_role not in ALL_ROLES:
            return None, f"Invalid role '{role}'. Allowed roles: {', '.join(ALL_ROLES)}"

        normalized_username = username.strip().lower()
        existing = User.query.filter_by(username=normalized_username).first()
        if existing:
            return None, f"Username '{normalized_username}' already exists."

        user = User(
            username=normalized_username,
            role=normalized_role,
            is_active=bool(is_active),
            created_at=time.time(),
            updated_at=time.time(),
        )
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
            logger.info("Created user '%s' with role '%s'", user.username, user.role)
            return user, None
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to persist user '%s': %s", normalized_username, ex)
            return None, "Database error creating user."

    @classmethod
    def authenticate(
        cls,
        username: str,
        password: str,
        expiry_seconds: Optional[float] = None,
        client_ip: str = "unknown",
    ) -> Tuple[Optional[User], Optional[str], Optional[float], Optional[str]]:
        """Authenticate user credentials and issue an active session token.
        
        Returns:
            Tuple of (user, raw_token, expires_at, error_message).
        """
        if not username or not password:
            return None, None, None, "Invalid username or password."

        normalized_username = str(username).strip().lower()
        user = User.query.filter_by(username=normalized_username).first()

        if not user or not user.check_password(str(password)):
            logger.warning("Failed authentication attempt for username '%s' from %s", normalized_username, client_ip)
            return None, None, None, "Invalid username or password."

        if not user.is_active:
            logger.warning("Authentication rejected for disabled account '%s' from %s", normalized_username, client_ip)
            return None, None, None, "Account is disabled. Please contact an administrator."

        # Issue bearer token
        raw_token = secrets.token_urlsafe(32)
        token_hash = cls.hash_token(raw_token)
        ttl = expiry_seconds if expiry_seconds is not None else cls.DEFAULT_TOKEN_EXPIRY_SECONDS
        now = time.time()
        expires_at = now + ttl

        token_rec = AuthTokenRecord(
            token_hash=token_hash,
            user_id=user.id,
            created_at=now,
            expires_at=expires_at,
            revoked=False,
            last_used_at=now,
        )
        user.last_login_at = now

        try:
            db.session.add(token_rec)
            db.session.commit()
            logger.info("User '%s' (role: %s) authenticated successfully from %s", user.username, user.role, client_ip)
            return user, raw_token, expires_at, None
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to store token for user '%s': %s", user.username, ex)
            return None, None, None, "Database error issuing authentication session."

    @classmethod
    def verify_token(cls, raw_token: str) -> Optional[User]:
        """Validate bearer token and retrieve associated active user."""
        if not raw_token or not isinstance(raw_token, str):
            return None

        clean_token = raw_token.strip()
        if not clean_token:
            return None

        token_hash = cls.hash_token(clean_token)
        now = time.time()

        try:
            token_rec = AuthTokenRecord.query.filter_by(token_hash=token_hash).first()
            if not token_rec:
                return None

            if not token_rec.is_valid(now=now):
                return None

            user = db.session.get(User, token_rec.user_id)
            if not user or not user.is_active:
                return None

            # Update last used timestamp periodically
            if token_rec.last_used_at is None or (now - token_rec.last_used_at) > 60.0:
                token_rec.last_used_at = now
                db.session.commit()

            return user
        except Exception as ex:
            logger.debug("Token verification query error: %s", ex)
            return None

    @classmethod
    def revoke_token(cls, raw_token: str) -> bool:
        """Revoke an active authentication token session (logout)."""
        if not raw_token or not isinstance(raw_token, str):
            return False

        token_hash = cls.hash_token(raw_token.strip())
        try:
            token_rec = AuthTokenRecord.query.filter_by(token_hash=token_hash).first()
            if token_rec:
                token_rec.revoked = True
                token_rec.revoked_at = time.time()
                db.session.commit()
                return True
            return False
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to revoke token: %s", ex)
            return False

    @classmethod
    def change_password(
        cls,
        user: User,
        current_password: str,
        new_password: str,
        min_password_length: Optional[int] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Change user password after verifying existing credential."""
        if not user.check_password(current_password):
            return False, "Current password is incorrect."

        valid, err = cls.validate_password(new_password, min_length=min_password_length)
        if not valid:
            return False, err

        try:
            user.set_password(new_password)
            # Invalidate all existing tokens on password change
            AuthTokenRecord.query.filter_by(user_id=user.id, revoked=False).update(
                {"revoked": True, "revoked_at": time.time()}
            )
            db.session.commit()
            logger.info("User '%s' successfully changed their password and revoked active sessions", user.username)
            return True, None
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed to update password for user '%s': %s", user.username, ex)
            return False, "Database error updating password."

    @classmethod
    def admin_reset_password(
        cls,
        user: User,
        new_password: str,
        admin_username: str,
        min_password_length: Optional[int] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Administratively reset a target user's password."""
        valid, err = cls.validate_password(new_password, min_length=min_password_length)
        if not valid:
            return False, err

        try:
            user.set_password(new_password)
            # Revoke all existing tokens for target user on admin reset
            AuthTokenRecord.query.filter_by(user_id=user.id, revoked=False).update(
                {"revoked": True, "revoked_at": time.time()}
            )
            db.session.commit()
            logger.info("Admin '%s' reset password for user '%s'", admin_username, user.username)
            return True, None
        except Exception as ex:
            db.session.rollback()
            logger.error("Failed admin reset password for user '%s': %s", user.username, ex)
            return False, "Database error resetting password."
