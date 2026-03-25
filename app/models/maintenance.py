"""Maintenance and work-log models."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from app.extensions import db


class MaintenanceRecord(db.Model):
    """A maintenance / repair work order."""

    __tablename__ = "maintenance_record"

    id: int = db.Column(db.Integer, primary_key=True)
    game_id: int | None = db.Column(
        db.Integer, db.ForeignKey("game.id"), nullable=True
    )
    work_order_type: str = db.Column(db.String(50), default="game")
    location_description: str | None = db.Column(db.String(200), nullable=True)
    issue_description: str = db.Column(db.Text, nullable=False)
    fix_description: str | None = db.Column(db.Text, nullable=True)
    work_notes: str | None = db.Column(db.Text, nullable=True)
    parts_used: str | None = db.Column(db.Text, nullable=True)
    cost: float | None = db.Column(db.Float, nullable=True)
    date_reported: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    date_fixed: datetime | None = db.Column(db.DateTime, nullable=True)
    status: str = db.Column(db.String(20), default="Open")
    priority: str = db.Column(db.String(20), default="Medium")
    technician: str | None = db.Column(db.String(50), nullable=True)
    photos: str | None = db.Column(db.Text, nullable=True)

    # Relationships
    work_logs = db.relationship(
        "WorkLog",
        backref="maintenance_record",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="WorkLog.timestamp",
    )

    # ------------------------------------------------------------------
    # Photo helpers (stored as JSON list in the ``photos`` column)
    # ------------------------------------------------------------------
    def get_photos(self) -> list[str]:
        """Return the list of photo filenames."""
        if self.photos:
            try:
                return json.loads(self.photos)
            except (json.JSONDecodeError, TypeError):
                return []
        return []

    def add_photo(self, filename: str) -> None:
        """Append *filename* to the photo list (no duplicates)."""
        photos = self.get_photos()
        if filename not in photos:
            photos.append(filename)
            self.photos = json.dumps(photos)

    def remove_photo(self, filename: str) -> None:
        """Remove *filename* from the photo list."""
        photos = self.get_photos()
        if filename in photos:
            photos.remove(filename)
            self.photos = json.dumps(photos) if photos else None

    def __repr__(self) -> str:
        return f"<MaintenanceRecord id={self.id} status={self.status!r}>"


class WorkLog(db.Model):
    """A time-stamped log entry on a maintenance record."""

    __tablename__ = "work_log"

    id: int = db.Column(db.Integer, primary_key=True)
    maintenance_id: int = db.Column(
        db.Integer, db.ForeignKey("maintenance_record.id"), nullable=False
    )
    user_id: int = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    work_description: str = db.Column(db.Text, nullable=False)
    parts_used: str | None = db.Column(db.Text, nullable=True)
    time_spent: float | None = db.Column(db.Float, nullable=True)
    cost_incurred: float | None = db.Column(db.Float, nullable=True)
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    user = db.relationship("User", backref="work_logs")

    def __repr__(self) -> str:
        return f"<WorkLog id={self.id} maintenance_id={self.maintenance_id}>"
