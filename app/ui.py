"""Presentation helpers shared by every template: how a stored value is shown.

One table decides which colour each status gets, so "Not_Working" is the same red on the
machine list, the dashboard and the machine page, and a new status value with no entry
shows as neutral rather than as an accidental "ok". Tones are the design-system status
classes: ``ok``, ``warn``, ``fault``, ``info`` and ``muted`` (static/css/components.css).
"""
from __future__ import annotations

from flask import Flask

# Every status-like value the application stores, by what it means for the floor.
TONES: dict[str, str] = {
    # Game.status
    "Working": "ok",
    "Not_Working": "fault",
    "Being_Fixed": "warn",
    "Retired": "muted",
    # Game.counter_status
    "Broken_Counter": "warn",
    "No_Counter": "muted",
    # MaintenanceRecord.status
    "Open": "fault",
    "In_Progress": "warn",
    "Fixed": "ok",
    "Deferred": "muted",
    # MaintenanceRecord.priority
    "Critical": "fault",
    "High": "warn",
    "Medium": "info",
    "Low": "muted",
    # InventoryRequest.status and urgency
    "Pending": "warn",
    "Approved": "info",
    "Ordered": "info",
    "Shipped": "info",
    "Received": "ok",
    "Rejected": "muted",
    "Urgent": "fault",
    "Normal": "muted",
    # GATBOX rail verdicts (app/routes/rails.py VERDICT)
    "held": "ok",
    "left": "warn",
    "over": "fault",
}

# Stored values whose display text is not just the value with underscores as spaces.
LABELS: dict[str, str] = {
    "Not_Working": "Not working",
    "Being_Fixed": "Being fixed",
    "Broken_Counter": "Counter broken",
    "No_Counter": "No counter",
    "In_Progress": "In progress",
    "held": "Held the window",
    "left": "Left the window",
    "over": "Over-voltage",
}


def status_tone(value: str | None) -> str:
    """The design-system tone for a stored status; ``muted`` for anything unknown."""
    return TONES.get(value or "", "muted")


def status_label(value: str | None) -> str:
    """Human text for a stored status: ``Not_Working`` -> ``Not working``."""
    if not value:
        return "—"
    return LABELS.get(value, value.replace("_", " "))


def register(app: Flask) -> None:
    app.add_template_filter(status_tone, "tone")
    app.add_template_filter(status_label, "status_label")
