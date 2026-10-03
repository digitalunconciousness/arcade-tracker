"""Rail-voltage sessions pushed in from GATBOX, and their traces.

A session is one contiguous run of the bench meter: one machine, one profile, one dial
mode. GATBOX decides where a session begins and ends, computes every statistic here, and
decides the verdict. **The hub stores; it does not recompute.** Two systems deriving the
same number from the same data is two chances to disagree about whether a machine passed.

The trace is downsampled on the Pi to at most 2000 points by a reducer that keeps each
bucket's extremes and never drops a spike, an alarm or an over-range reading, so the shape
survives. The full-resolution CSV stays on the Pi, which is its archive.

See ``contract/v1/README.md`` for the wire format and the uid rules.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db

# verdict.state, decided by GATBOX. None when the profile has no window at all -- a bench
# or free-measurement profile has nothing to pass or fail against.
VERDICTS = ("held", "left", "over")


class RailSession(db.Model):
    """One metered session, as GATBOX summarised it."""

    __tablename__ = "rail_session"

    id: int = db.Column(db.Integer, primary_key=True)
    # The contract's deterministic id: sha256(public_id|rail_session|file)[:32].
    uid: str = db.Column(db.String(32), unique=True, nullable=False)
    device_id: int = db.Column(
        db.Integer, db.ForeignKey("device.id"), nullable=False
    )
    game_id: int | None = db.Column(
        db.Integer, db.ForeignKey("game.id"), nullable=True
    )
    # The Pi's CSV name. Its only identity there, and what makes the uid reproducible.
    file: str = db.Column(db.String(64), nullable=False)

    started: datetime | None = db.Column(db.DateTime, nullable=True)
    ended: datetime | None = db.Column(db.DateTime, nullable=True)
    duration_s: float | None = db.Column(db.Float, nullable=True)
    samples: int | None = db.Column(db.Integer, nullable=True)
    rate: float | None = db.Column(db.Float, nullable=True)
    timebase: str | None = db.Column(db.String(30), nullable=True)

    # What the Pi believed the time was. 'unverified' means absolute times may be wrong
    # and only the readings' monotonic uptime should be trusted for relative timing.
    clock: str | None = db.Column(db.String(12), nullable=True)
    clock_ntp_from: datetime | None = db.Column(db.DateTime, nullable=True)

    profile_id: str | None = db.Column(db.String(40), nullable=True)
    profile_label: str | None = db.Column(db.String(60), nullable=True)
    profile_kind: str | None = db.Column(db.String(10), nullable=True)
    rail: str | None = db.Column(db.String(10), nullable=True)
    mode: str | None = db.Column(db.String(10), nullable=True)

    # All null together for a bench profile: nothing to compare against.
    window_lo: float | None = db.Column(db.Float, nullable=True)
    window_hi: float | None = db.Column(db.Float, nullable=True)
    window_unit: str | None = db.Column(db.String(8), nullable=True)
    window_source: str | None = db.Column(db.String(40), nullable=True)
    alarm_hi: float | None = db.Column(db.Float, nullable=True)

    # Statistics over readings taken while the board was actually powered, in the
    # profile's modes, excluding autorange glitches. GATBOX's definition, not ours.
    powered_mean: float | None = db.Column(db.Float, nullable=True)
    powered_min: float | None = db.Column(db.Float, nullable=True)
    powered_max: float | None = db.Column(db.Float, nullable=True)
    powered_readings: int | None = db.Column(db.Integer, nullable=True)
    in_window_pct: float | None = db.Column(db.Float, nullable=True)

    verdict: str | None = db.Column(db.String(10), nullable=True)
    verdict_detail: str | None = db.Column(db.Text, nullable=True)

    over_voltage: int = db.Column(db.Integer, default=0)
    excursions: int = db.Column(db.Integer, default=0)
    power_cycles: int = db.Column(db.Integer, default=0)
    gaps: int = db.Column(db.Integer, default=0)
    ol_events: int = db.Column(db.Integer, default=0)
    marks: int = db.Column(db.Integer, default=0)
    suspect: int = db.Column(db.Integer, default=0)

    received: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    #
    # No cascade from the machine on purpose: deleting a Game nulls game_id and leaves the
    # session, because diagnostic history is the device's record of what it measured, not
    # the machine row's property. Losing a year of rail traces by tidying up a duplicate
    # cabinet entry would be a nasty surprise. The cascade that does apply is from the
    # device, since a session cannot be read without knowing which box recorded it.
    game = db.relationship("Game", backref="rail_sessions")
    readings = db.relationship(
        "Reading",
        backref="rail_session",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="Reading.epoch",
    )
    orders = db.relationship(
        "MaintenanceRecord",
        backref="rail_session",
        lazy=True,
        order_by="MaintenanceRecord.date_reported",
    )

    def __repr__(self) -> str:
        return f"<RailSession {self.file!r} {self.verdict or 'no verdict'}>"


class Reading(db.Model):
    """One point of a session's downsampled trace."""

    __tablename__ = "reading"

    id: int = db.Column(db.Integer, primary_key=True)
    # sha256(public_id|reading|file|epoch:.3f)[:32]. The ".3f" is contractual: formatting
    # the same reading to more places yields a different uid and duplicates the trace.
    uid: str = db.Column(db.String(32), unique=True, nullable=False)
    # Indexed because drawing a trace means "every reading for this session, in order".
    # This is the first non-unique index in the schema, and it is here on purpose.
    rail_session_id: int = db.Column(
        db.Integer, db.ForeignKey("rail_session.id"), nullable=False, index=True
    )

    epoch: float = db.Column(db.Float, nullable=False)
    # The Pi's monotonic uptime. Correct even when the wall clock is not, so relative
    # timing within a session should use this rather than epoch.
    up: float | None = db.Column(db.Float, nullable=True)
    # Base units (volts, amps, ohms). Null for an over-range reading, where the meter
    # reported infinity and there is no value to store.
    v: float | None = db.Column(db.Float, nullable=True)
    # What the meter actually printed, SI prefix and all ("4.0" with unit "mV"). Kept so a
    # readings table can show the meter face rather than a normalised number.
    raw: str | None = db.Column(db.String(16), nullable=True)
    unit: str | None = db.Column(db.String(8), nullable=True)
    mode: str | None = db.Column(db.String(10), nullable=True)
    # ok / spike / alarm, or null where the rule does not apply (no limit, wrong dial
    # mode, or over-range). GATBOX's live and after-the-fact rules are deliberately equal.
    alarm: str | None = db.Column(db.String(6), nullable=True)
    ol: bool = db.Column(db.Boolean, default=False, nullable=False)

    def __repr__(self) -> str:
        return f"<Reading {self.epoch} {self.raw!r}>"
