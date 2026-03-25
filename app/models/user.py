"""User model with role-based access control."""

from __future__ import annotations

import datetime as dt
from datetime import datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


class User(UserMixin, db.Model):
    """Application user with role-based access control.

    Roles (ascending privilege): readonly → operator → manager → admin.
    """

    __tablename__ = "user"

    id: int = db.Column(db.Integer, primary_key=True)
    username: str = db.Column(db.String(80), unique=True, nullable=False)
    password_hash: str = db.Column(db.String(120), nullable=False)
    role: str = db.Column(db.String(20), nullable=False, default="readonly")
    is_active: bool = db.Column(db.Boolean, default=True)
    created_at: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(dt.UTC)
    )
    must_change_password: bool = db.Column(db.Boolean, default=True)
    profile_picture: str | None = db.Column(db.String(255), nullable=True)
    last_login: datetime | None = db.Column(db.DateTime, nullable=True)

    ROLE_HIERARCHY: dict[str, int] = {
        "readonly": 1,
        "operator": 2,
        "manager": 3,
        "admin": 4,
    }

    # ------------------------------------------------------------------
    # Password helpers
    # ------------------------------------------------------------------
    def set_password(self, password: str) -> None:
        """Hash and store *password*."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Return ``True`` if *password* matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    # ------------------------------------------------------------------
    # Role helpers
    # ------------------------------------------------------------------
    def has_role(self, role: str) -> bool:
        """Return ``True`` if the user's role is >= *role* in the hierarchy."""
        user_level = self.ROLE_HIERARCHY.get(self.role, 0)
        required_level = self.ROLE_HIERARCHY.get(role, 0)
        return user_level >= required_level

    # ------------------------------------------------------------------
    # Flask-Login interface
    # ------------------------------------------------------------------
    def get_id(self) -> str:
        return str(self.id)

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role!r}>"
