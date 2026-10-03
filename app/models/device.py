"""Machine clients that push data into the hub.

A device is not a user. It has no session, no role and no access to anything a person
sees — it authenticates with a bearer token to the ``api_v1`` blueprint and nothing else.
Today there is exactly one: the GATBOX Pi.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db

# A token reads gbx_<public_id>.<secret>. The public id is stored in the clear and indexed,
# because the secret is hashed and a hash cannot be looked up by -- the device has to be
# found before its secret can be checked. Same split as a GitHub personal access token.
TOKEN_PREFIX = "gbx_"
PUBLIC_ID_CHARS = 12          # hex; 48 bits is plenty to name a handful of devices
SECRET_BYTES = 32             # -> 43 characters of URL-safe base64


class Device(db.Model):
    """A machine client allowed to post to the v1 API."""

    __tablename__ = "device"

    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(60), unique=True, nullable=False)
    public_id: str = db.Column(db.String(32), unique=True, nullable=False)
    token_hash: str = db.Column(db.String(256), nullable=False)
    enabled: bool = db.Column(db.Boolean, default=True, nullable=False)
    created: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_seen: datetime | None = db.Column(db.DateTime, nullable=True)
    last_ip: str | None = db.Column(db.String(45), nullable=True)
    notes: str | None = db.Column(db.Text, nullable=True)

    # Relationships
    rail_sessions = db.relationship(
        "RailSession",
        backref="device",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="RailSession.started",
    )

    # ------------------------------------------------------------------
    # Token helpers
    # ------------------------------------------------------------------
    @staticmethod
    def new_public_id() -> str:
        return secrets.token_hex(PUBLIC_ID_CHARS // 2)

    def issue_token(self) -> str:
        """Mint a new token, store only its hash, and return it once.

        The caller is the only chance anyone has to see this value. Nothing in the
        application can recover it afterwards, which is the point: a leaked database
        does not leak a working token.
        """
        if not self.public_id:
            self.public_id = self.new_public_id()
        secret = secrets.token_urlsafe(SECRET_BYTES)
        self.token_hash = generate_password_hash(secret)
        return f"{TOKEN_PREFIX}{self.public_id}.{secret}"

    def check_secret(self, secret: str) -> bool:
        """Whether *secret* is this device's token secret."""
        return check_password_hash(self.token_hash, secret)

    @staticmethod
    def split_token(token: str) -> tuple[str, str] | None:
        """``gbx_<public_id>.<secret>`` -> ``(public_id, secret)``, or None if malformed.

        Shape only; it proves nothing about the token being real.
        """
        if not token or not token.startswith(TOKEN_PREFIX):
            return None
        body = token[len(TOKEN_PREFIX):]
        public_id, _, secret = body.partition(".")
        if not public_id or not secret:
            return None
        return public_id, secret

    def __repr__(self) -> str:
        return f"<Device {self.name!r}>"
