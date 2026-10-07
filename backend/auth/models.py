"""NetSentinel Authentication & User Models.

Provides SQLAlchemy database models for users, password hashing, and
cryptographically hashed API authentication tokens.
"""

import time
from typing import Any, Dict, Optional
from werkzeug.security import check_password_hash, generate_password_hash

from database import db


class User(db.Model):
    """SQLAlchemy model representing an authorized NetSentinel operator/user."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False, default="VIEWER", index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    created_at = db.Column(db.Float, nullable=False, default=time.time)
    updated_at = db.Column(db.Float, nullable=False, default=time.time)
    last_login_at = db.Column(db.Float, nullable=True)

    tokens = db.relationship(
        "AuthTokenRecord",
        backref="user",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if "is_active" not in kwargs:
            self.is_active = True
        if "role" not in kwargs:
            self.role = "VIEWER"
        if "created_at" not in kwargs:
            self.created_at = time.time()
        if "updated_at" not in kwargs:
            self.updated_at = time.time()

    def set_password(self, password: str) -> None:
        """Hash and update user password."""
        self.password_hash = generate_password_hash(password)
        self.updated_at = time.time()

    def check_password(self, password: str) -> bool:
        """Verify candidate plaintext password against stored hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> Dict[str, Any]:
        """Convert user instance to a safe JSON-serializable dictionary.
        
        Strictly excludes password_hash from serialized outputs.
        """
        from auth.roles import get_role_permissions
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "permissions": sorted(list(get_role_permissions(self.role))),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_login_at": self.last_login_at,
        }


class AuthTokenRecord(db.Model):
    """SQLAlchemy model representing a cryptographically hashed authentication token session."""
    __tablename__ = "auth_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = db.Column(db.Float, nullable=False, default=time.time)
    expires_at = db.Column(db.Float, nullable=False, index=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False, index=True)
    revoked_at = db.Column(db.Float, nullable=True)
    last_used_at = db.Column(db.Float, nullable=True)

    def is_valid(self, now: Optional[float] = None) -> bool:
        """Check whether the token is currently active, unrevoked, and unexpired."""
        current_time = now if now is not None else time.time()
        return not self.revoked and self.expires_at > current_time
