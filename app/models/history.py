"""A machine's location and status over time (feature step 1).

Every move between Floor and Warehouse, and every change of status, becomes one row, with when
and who. Downtime, the rotation planner and the collection round are all built on it.

Rows are written by a ``before_flush`` hook (app/services/history.py), not by the pages that
change a machine, so no code path can forget to: the edit form, the bulk update, the roster
import, a script, or whatever comes next.

``kind`` is ``location`` or ``status``. ``source`` says what wrote it:

* ``created``  -- the machine was added; ``old_value`` is empty;
* ``change``   -- someone changed it;
* ``baseline`` -- the value it had when history started (migration d1e2f3a4b5c6). It means
  "tracked from here", not "arrived here then": that date isn't known, and isn't guessed.
"""
from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db

KINDS = ("location", "status")
SOURCES = ("created", "change", "baseline")


def _utc_now() -> datetime:
    """Naive UTC, like every other timestamp column here."""
    return datetime.now(UTC).replace(tzinfo=None)


class GameEvent(db.Model):
    __tablename__ = "game_event"
    __table_args__ = (
        # A machine's history in time order: the machine page, downtime, the planner.
        db.Index("ix_game_event_game_id_occurred_at", "game_id", "occurred_at"),
    )

    id: int = db.Column(db.Integer, primary_key=True)
    game_id: int = db.Column(db.Integer, db.ForeignKey("game.id", ondelete="CASCADE"),
                             nullable=False)
    kind: str = db.Column(db.String(10), nullable=False)
    old_value: str | None = db.Column(db.String(20), nullable=True)
    new_value: str = db.Column(db.String(20), nullable=False)
    occurred_at: datetime = db.Column(db.DateTime, nullable=False, default=_utc_now)
    user_id: int | None = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"),
                                    nullable=True, index=True)
    source: str = db.Column(db.String(10), nullable=False, default="change")
    # The work order that made this change, when one did (app/services/downtime.py).
    maintenance_id: int | None = db.Column(
        db.Integer, db.ForeignKey("maintenance_record.id", ondelete="SET NULL",
                                  name="fk_game_event_maintenance_id"),
        nullable=True, index=True)

    game = db.relationship("Game")
    user = db.relationship("User")
    order = db.relationship("MaintenanceRecord")

    def __repr__(self) -> str:
        return (f"<GameEvent game={self.game_id} {self.kind} {self.old_value!r}->"
                f"{self.new_value!r} {self.occurred_at:%Y-%m-%d}>")
