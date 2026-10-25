"""Preventive maintenance tasks (feature step 5): work that comes due by plays or by days.

A task says what to do, how often (every N plays, every N days, or both -- whichever comes
first) and to which machines: every machine, all pinball or all video, or one machine. When it
comes due on a machine, a playable work order is raised for it (app/services/upkeep.py); the
order carries ``pm_task_id``, and closing it as Fixed starts the count again. There is no
"last done" column: the task's own orders are the record of when it was done.
"""
from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db

APPLIES_TO = {"all": "Every machine", "pinball": "All pinball", "video": "All video",
              "machine": "One machine"}


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class MaintenanceTask(db.Model):
    __tablename__ = "maintenance_task"

    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(100), nullable=False)
    instructions: str | None = db.Column(db.Text, nullable=True)
    every_plays: int | None = db.Column(db.Integer, nullable=True)
    every_days: int | None = db.Column(db.Integer, nullable=True)
    applies_to: str = db.Column(db.String(10), nullable=False, default="all")
    # Only for applies_to == "machine". Deleting the machine deletes its own tasks.
    game_id: int | None = db.Column(db.Integer, db.ForeignKey("game.id", ondelete="CASCADE"),
                                    nullable=True, index=True)
    active: bool = db.Column(db.Boolean, nullable=False, default=True)
    # The count starts here for a machine it has never been done on, so a new task doesn't
    # find every machine overdue on its first day.
    created_at: datetime = db.Column(db.DateTime, nullable=False, default=_utc_now)
    created_by_id: int | None = db.Column(
        db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True, index=True)

    game = db.relationship("Game")
    created_by = db.relationship("User")

    @property
    def rule(self) -> str:
        parts = []
        if self.every_plays:
            parts.append(f"{self.every_plays:,} plays")
        if self.every_days:
            parts.append(f"{self.every_days:,} days")
        return "Every " + " or ".join(parts) + (", whichever comes first" if len(parts) > 1
                                                 else "")

    @property
    def scope(self) -> str:
        if self.applies_to == "machine":
            return self.game.name if self.game else "A deleted machine"
        return APPLIES_TO.get(self.applies_to, self.applies_to)

    def __repr__(self) -> str:
        return f"<MaintenanceTask {self.name!r} {self.applies_to}>"
