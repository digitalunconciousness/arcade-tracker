"""Dashboard blueprint — home / index page."""

import datetime as dt
from datetime import datetime, date

from flask import Blueprint, render_template
from flask_login import login_required

from app.extensions import db
from app.models import Game, PlayRecord, MaintenanceRecord, LowStockAlert


dashboard_bp = Blueprint("dashboard", __name__)


def _update_monthly_rankings_if_due():
    """Increment Top5/Top10 counters once per calendar month.

    Considers only Floor games with Working counters.  Uses PlayRecord
    revenue summed over the previous calendar month.  Safe to call
    multiple times — updates at most once per month.
    """
    today = date.today()
    current_month_start = today.replace(day=1)

    # Determine previous month range
    prev_month_end = current_month_start - dt.timedelta(days=1)
    prev_month_start = prev_month_end.replace(day=1)

    # Check if rankings already updated this month
    last_updates = db.session.query(
        db.func.max(Game.last_ranking_update)
    ).scalar()
    if last_updates and last_updates >= current_month_start:
        return  # Already updated for this month

    # Build revenue per game for previous month
    records = (
        PlayRecord.query.join(Game)
        .filter(
            PlayRecord.date_recorded >= prev_month_start,
            PlayRecord.date_recorded <= prev_month_end,
            Game.location == "Floor",
            Game.counter_status == "Working",
        )
        .all()
    )

    if not records:
        # Mark update to avoid repeated work this month even if no data
        for g in Game.query.all():
            g.last_ranking_update = current_month_start
        db.session.commit()
        return

    revenue_by_game: dict[int, float] = {}
    for r in records:
        revenue_by_game.setdefault(r.game_id, 0.0)
        revenue_by_game[r.game_id] += r.revenue or 0.0

    # Rank games by revenue
    ranked = sorted(revenue_by_game.items(), key=lambda kv: kv[1], reverse=True)

    top5_ids = {gid for gid, _ in ranked[:5]}
    top10_ids = {gid for gid, _ in ranked[:10]}

    games = Game.query.all()
    for g in games:
        if g.id in top5_ids:
            g.times_in_top_5 = (g.times_in_top_5 or 0) + 1
        if g.id in top10_ids:
            g.times_in_top_10 = (g.times_in_top_10 or 0) + 1
        g.last_ranking_update = current_month_start

    db.session.commit()


@dashboard_bp.route("/")
@login_required
def home():
    # Update monthly rankings if needed (idempotent)
    _update_monthly_rankings_if_due()

    # Fetch data for dashboard
    all_games = Game.query.all()
    floor_games = Game.query.filter_by(location="Floor").all()
    total_games = len(all_games)
    total_plays = sum(game.total_plays for game in all_games)
    total_revenue = sum(game.total_revenue for game in all_games)

    # Get recent records and maintenance
    recent_records = (
        PlayRecord.query.order_by(PlayRecord.date_recorded.desc()).limit(5).all()
    )
    recent_maintenance = (
        MaintenanceRecord.query.filter_by(status="Open").limit(5).all()
    )

    # Get low stock alerts
    low_stock_alerts = (
        LowStockAlert.query.filter_by(resolved=False).limit(10).all()
    )

    # Calculate worst performers
    worst_performers = []
    if floor_games:
        performers = []
        for game in floor_games:
            if game.counter_status != "Working":
                continue
            date_added = game.date_added
            if date_added.tzinfo is None:
                date_added = date_added.replace(tzinfo=dt.UTC)
            days_active = max((datetime.now(dt.UTC) - date_added).days, 1)
            daily_revenue_avg = game.total_revenue / days_active
            performers.append((game, daily_revenue_avg))
        worst_performers = sorted(performers, key=lambda x: x[1])[:3]

    return render_template(
        "index.html",
        total_games=total_games,
        floor_games=floor_games,
        total_plays=total_plays,
        total_revenue=total_revenue,
        recent_records=recent_records,
        recent_maintenance=recent_maintenance,
        worst_performers=worst_performers,
        low_stock_alerts=low_stock_alerts,
    )
