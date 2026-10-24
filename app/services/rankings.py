"""Monthly Top 5 / Top 10 counters.

This used to exist twice, as ``dashboard._update_monthly_rankings_if_due`` and
``reports.update_monthly_rankings_if_due`` (F-3); both pages still run it on GET (F-14),
now through this one function.
"""
from __future__ import annotations

import datetime as dt
from datetime import date

from app.extensions import db
from app.models import Game, PlayRecord


def update_monthly_rankings_if_due(today: date | None = None) -> bool:
    """Count last month's top earners once per calendar month. Returns True if it ran.

    Only floor machines with a working counter are ranked, on PlayRecord revenue over the
    previous calendar month. Idempotent: a second call in the same month does nothing.
    """
    today = today or date.today()
    current_month_start = today.replace(day=1)
    prev_month_end = current_month_start - dt.timedelta(days=1)
    prev_month_start = prev_month_end.replace(day=1)

    last = db.session.query(db.func.max(Game.last_ranking_update)).scalar()
    if last and last >= current_month_start:
        return False

    revenue = dict(
        db.session.query(PlayRecord.game_id, db.func.sum(PlayRecord.revenue))
        .join(Game)
        .filter(
            PlayRecord.date_recorded >= prev_month_start,
            PlayRecord.date_recorded <= prev_month_end,
            Game.location == "Floor",
            Game.counter_status == "Working",
        )
        .group_by(PlayRecord.game_id)
        .all()
    )
    ranked = sorted(revenue.items(), key=lambda kv: kv[1] or 0.0, reverse=True)
    top5 = {gid for gid, _ in ranked[:5]}
    top10 = {gid for gid, _ in ranked[:10]}

    for game in Game.query.all():
        if game.id in top5:
            game.times_in_top_5 = (game.times_in_top_5 or 0) + 1
        if game.id in top10:
            game.times_in_top_10 = (game.times_in_top_10 or 0) + 1
        game.last_ranking_update = current_month_start
    db.session.commit()
    return True
