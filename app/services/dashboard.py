"""The dashboard: what needs attention on the floor today."""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import joinedload

from app.models import Game, InventoryItem, LowStockAlert, MaintenanceRecord, PlayRecord

OPEN = ("Open", "In_Progress")
PRIORITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
DOWN = ("Not_Working", "Being_Fixed")


@dataclass
class Dashboard:
    total_games: int
    floor_games: list[Game]
    down_games: list[Game]
    total_plays: int
    total_revenue: float
    open_orders: list[MaintenanceRecord]
    open_order_count: int
    recent_records: list[PlayRecord]
    low_stock: list[LowStockAlert]
    worst_performers: list[tuple[Game, float]]


def _per_day(game: Game) -> float:
    added = game.date_added
    if added.tzinfo is None:
        added = added.replace(tzinfo=dt.UTC)
    days = max((datetime.now(dt.UTC) - added).days, 1)
    return (game.total_revenue or 0.0) / days


def build_dashboard() -> Dashboard:
    games = Game.query.order_by(Game.name).all()
    floor = [g for g in games if g.location == "Floor"]

    open_orders = (
        MaintenanceRecord.query.options(joinedload(MaintenanceRecord.game))
        .filter(MaintenanceRecord.status.in_(OPEN))
        .all()
    )
    open_orders.sort(key=lambda o: (PRIORITY_ORDER.get(o.priority, 9),
                                    -(o.date_reported.timestamp() if o.date_reported else 0)))

    recent = (
        PlayRecord.query.options(joinedload(PlayRecord.game))
        .order_by(PlayRecord.date_recorded.desc(), PlayRecord.id.desc())
        .limit(5)
        .all()
    )
    low = (
        LowStockAlert.query.options(joinedload(LowStockAlert.item))
        .join(InventoryItem)
        .filter(LowStockAlert.resolved.is_(False))
        .order_by(InventoryItem.name)
        .limit(10)
        .all()
    )
    working_floor = [g for g in floor if g.counter_status == "Working"]
    worst = sorted(((g, _per_day(g)) for g in working_floor), key=lambda gp: gp[1])[:3]

    return Dashboard(
        total_games=len(games),
        floor_games=floor,
        down_games=[g for g in games if g.status in DOWN and g.location == "Floor"],
        total_plays=sum(g.total_plays or 0 for g in games),
        total_revenue=sum(g.total_revenue or 0.0 for g in games),
        open_orders=open_orders[:6],
        open_order_count=len(open_orders),
        recent_records=recent,
        low_stock=low,
        worst_performers=worst,
    )
