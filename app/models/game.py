"""Game and play-record models."""

from __future__ import annotations

import datetime as dt
from datetime import date, datetime

from app.extensions import db


class Game(db.Model):
    """An arcade game tracked by the system."""

    __tablename__ = "game"

    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(100), nullable=False)
    manufacturer: str | None = db.Column(db.String(50), nullable=True)
    year: int | None = db.Column(db.Integer, nullable=True)
    genre: str | None = db.Column(db.String(50), nullable=True)
    location: str = db.Column(db.String(20), default="Warehouse")
    floor_position: str | None = db.Column(db.String(50), nullable=True)
    warehouse_section: str | None = db.Column(db.String(50), nullable=True)
    status: str = db.Column(db.String(20), default="Working")
    coins_per_play: float = db.Column(db.Float, default=0.25)
    total_plays: int = db.Column(db.Integer, default=0)
    total_revenue: float = db.Column(db.Float, default=0.0)
    counter_status: str = db.Column(db.String(20), default="Working")
    counter_notes: str | None = db.Column(db.Text, nullable=True)
    date_added: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(dt.UTC)
    )
    notes: str | None = db.Column(db.Text, nullable=True)
    image_filename: str | None = db.Column(db.String(255), nullable=True)
    times_in_top_5: int = db.Column(db.Integer, default=0)
    times_in_top_10: int = db.Column(db.Integer, default=0)
    last_ranking_update: date | None = db.Column(db.Date, nullable=True)

    # Relationships
    play_records = db.relationship(
        "PlayRecord", backref="game", lazy=True, cascade="all, delete-orphan"
    )
    maintenance_records = db.relationship(
        "MaintenanceRecord", backref="game", lazy=True, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Game {self.name!r}>"


class PlayRecord(db.Model):
    """A single play-count / coin-count snapshot for a game."""

    __tablename__ = "play_record"

    id: int = db.Column(db.Integer, primary_key=True)
    game_id: int = db.Column(
        db.Integer, db.ForeignKey("game.id"), nullable=False
    )
    coin_count: int = db.Column(db.Integer, nullable=False, default=0)
    plays_count: int = db.Column(db.Integer, nullable=False, default=0)
    revenue: float = db.Column(db.Float, nullable=False, default=0.0)
    date_recorded: date = db.Column(db.Date, nullable=False, default=date.today)
    notes: str | None = db.Column(db.Text, nullable=True)

    def __repr__(self) -> str:
        return f"<PlayRecord game_id={self.game_id} date={self.date_recorded}>"
