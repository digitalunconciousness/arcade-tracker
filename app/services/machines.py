"""The machine page: everything one cabinet's page shows, gathered in one place."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

from app.models import Game, MaintenanceRecord, PlayRecord, RailSession

OPEN_STATUSES = ("Open", "In_Progress")
RECENT_PLAYS = 10
RECENT_CLOSED = 10


@dataclass
class MachinePage:
    game: Game
    open_orders: list[MaintenanceRecord]
    closed_orders: list[MaintenanceRecord]
    closed_total: int
    recent_plays: list[PlayRecord]
    can_add_baseline: bool
    rail_last: RailSession | None
    rail_count: int
    daily_revenue: float | None
    manual_url: str
    extra: dict = field(default_factory=dict)

    @property
    def can_record_plays(self) -> bool:
        return self.game.counter_status == "Working"


def klov_url(name: str) -> str:
    """The machine's page in the Killer List of Videogames, where its manuals live.

    The same slug rules the old template applied inline: lower case, spaces and dots to
    hyphens, '&' to 'and', and ! ( ) : ' dropped.
    """
    slug = name.lower().replace("&", "and")
    slug = re.sub(r"[ .]", "-", slug)
    slug = re.sub(r"[!():']", "", slug)
    return f"https://www.arcade-museum.com/Videogame/{slug}#manuals"


def machine_page(game: Game, today: date | None = None) -> MachinePage:
    orders = (
        MaintenanceRecord.query.filter_by(game_id=game.id)
        .order_by(MaintenanceRecord.date_reported.desc(), MaintenanceRecord.id.desc())
        .all()
    )
    open_orders = [o for o in orders if o.status in OPEN_STATUSES]
    closed = [o for o in orders if o.status not in OPEN_STATUSES]

    recent_plays = (
        PlayRecord.query.filter_by(game_id=game.id)
        .order_by(PlayRecord.date_recorded.desc(), PlayRecord.id.desc())
        .limit(RECENT_PLAYS)
        .all()
    )
    any_plays = recent_plays or PlayRecord.query.filter_by(game_id=game.id).first()

    rail_last = (
        RailSession.query.filter_by(game_id=game.id)
        .order_by(RailSession.started.desc().nullslast(), RailSession.id.desc())
        .first()
    )
    rail_count = RailSession.query.filter_by(game_id=game.id).count()

    daily = None
    if game.date_added:
        days = ((today or date.today()) - game.date_added.date()).days or 1
        daily = (game.total_revenue or 0.0) / days

    return MachinePage(
        game=game,
        open_orders=open_orders,
        closed_orders=closed[:RECENT_CLOSED],
        closed_total=len(closed),
        recent_plays=recent_plays,
        can_add_baseline=not any_plays,
        rail_last=rail_last,
        rail_count=rail_count,
        daily_revenue=daily,
        manual_url=klov_url(game.name),
    )
