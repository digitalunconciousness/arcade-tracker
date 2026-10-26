"""Alerts (feature step 6): tell people when something happens, on their phones.

A channel is one destination with its own list of events: say "Techs" gets coin-door reports
and machines down, "Manager" gets low stock and the round's flags. A channel sends to an ntfy
topic (the free phone app, on the arcade's own ntfy server), a Discord webhook, or both.

Every alert is first written to ``alert``, the outbox, in the same transaction as whatever
caused it; ``scripts/send_alerts.py``, run every minute by a systemd timer, delivers them.
So a page never waits on the internet, and an alert raised while the connection is down is
retried, not lost. One row per channel and target, so a Discord outage doesn't hold up ntfy.
"""
from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db

EVENTS = {
    "coin_door": "Problem reported from a coin door",
    "machine_down": "Machine marked down",
    "rail_window": "GATBOX rail outside its window",
    "low_stock": "Part at or below minimum stock",
    "pm_due": "Preventive maintenance due",
    "round_flag": "Collection round flags",
    "part_request": "Part request shipped or received",
    "summary": "Daily summary at opening",
}
TARGETS = ("ntfy", "discord")
STATES = ("pending", "held", "sent", "failed")


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class AlertChannel(db.Model):
    __tablename__ = "alert_channel"

    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(60), nullable=False)
    # Full topic address, e.g. https://ntfy.example.com/arcade-techs-3f9c...
    ntfy_url: str | None = db.Column(db.String(500), nullable=True)
    # An access token, when the ntfy server requires one. A secret: never shown back.
    ntfy_token: str | None = db.Column(db.String(200), nullable=True)
    # Anyone holding a webhook address can post to the channel: a secret too.
    discord_webhook: str | None = db.Column(db.String(500), nullable=True)
    events: str = db.Column(db.Text, nullable=False, default="")    # comma-separated EVENTS keys
    # Hold alerts outside opening hours and send them together at opening.
    quiet: bool = db.Column(db.Boolean, nullable=False, default=True)
    active: bool = db.Column(db.Boolean, nullable=False, default=True)
    created_at: datetime = db.Column(db.DateTime, nullable=False, default=_utc_now)

    @property
    def event_list(self) -> list[str]:
        return [e for e in (self.events or "").split(",") if e in EVENTS]

    @property
    def targets(self) -> list[str]:
        return [t for t, on in (("ntfy", self.ntfy_url), ("discord", self.discord_webhook)) if on]

    def wants(self, event: str) -> bool:
        return self.active and event in self.event_list

    def __repr__(self) -> str:
        return f"<AlertChannel {self.name!r}>"


class Alert(db.Model):
    __tablename__ = "alert"
    __table_args__ = (
        # The sender's one query: what is waiting, and when it may next be tried.
        db.Index("ix_alert_status_next_try_at", "status", "next_try_at"),
    )

    id: int = db.Column(db.Integer, primary_key=True)
    channel_id: int = db.Column(db.Integer,
                                db.ForeignKey("alert_channel.id", ondelete="CASCADE"),
                                nullable=False, index=True)
    target: str = db.Column(db.String(10), nullable=False)
    event: str = db.Column(db.String(20), nullable=False)
    title: str = db.Column(db.String(200), nullable=False)
    body: str = db.Column(db.Text, nullable=False, default="")
    path: str | None = db.Column(db.String(300), nullable=True)   # page to open, on this site
    created_at: datetime = db.Column(db.DateTime, nullable=False, default=_utc_now)
    status: str = db.Column(db.String(10), nullable=False, default="pending")
    attempts: int = db.Column(db.Integer, nullable=False, default=0)
    next_try_at: datetime | None = db.Column(db.DateTime, nullable=True)
    sent_at: datetime | None = db.Column(db.DateTime, nullable=True)
    error: str | None = db.Column(db.String(300), nullable=True)

    channel = db.relationship("AlertChannel")

    def __repr__(self) -> str:
        return f"<Alert {self.event} {self.target} {self.status}>"


class Setting(db.Model):
    """Small settings kept in the database, edited on admin pages: opening hours, and the
    date the last daily summary went out."""

    __tablename__ = "app_setting"

    key: str = db.Column(db.String(50), primary_key=True)
    value: str | None = db.Column(db.Text, nullable=True)

    @classmethod
    def get(cls, key: str, default: str | None = None) -> str | None:
        row = db.session.get(cls, key)
        return row.value if row is not None and row.value is not None else default

    @classmethod
    def put(cls, key: str, value: str | None) -> None:
        row = db.session.get(cls, key)
        if row is None:
            db.session.add(cls(key=key, value=value))
        else:
            row.value = value
