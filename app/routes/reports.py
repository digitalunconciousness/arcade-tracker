"""Reports blueprint — revenue reports, graphs, PDF/CSV export."""

import io
import os
import datetime as dt
from collections import Counter
from datetime import date, datetime, timedelta

import pandas as pd
from flask import (
    Blueprint,
    current_app,
    make_response,
    render_template,
    request,
    send_file,
)
from flask_login import login_required
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.extensions import db
from app.models import (
    Game,
    InventoryItem,
    InventoryRequest,
    MaintenanceRecord,
    PlayRecord,
)
from app.utils.decorators import requires_role

reports_bp = Blueprint("reports", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _update_top_rankings():
    """Deprecated: replaced by update_monthly_rankings_if_due()."""
    return


def update_monthly_rankings_if_due():
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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@reports_bp.route("/reports")
@login_required
@requires_role("manager")
def reports():
    thirty_days_ago = date.today() - timedelta(days=30)
    recent_records = PlayRecord.query.filter(
        PlayRecord.date_recorded >= thirty_days_ago
    ).all()

    # Calculate daily revenue
    daily_revenue: dict[str, float] = {}
    for record in recent_records:
        day = record.date_recorded.strftime("%Y-%m-%d")
        daily_revenue[day] = daily_revenue.get(day, 0) + record.revenue

    # Top and worst performers — only floor games with working counters
    floor_games = Game.query.filter_by(location="Floor", counter_status="Working").all()
    performers = []
    for game in floor_games:
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue_avg = game.total_revenue / days_active
        performers.append(
            {
                "game": {
                    "id": game.id,
                    "name": game.name,
                    "times_in_top_5": game.times_in_top_5,
                    "times_in_top_10": game.times_in_top_10,
                },
                "daily_revenue": daily_revenue_avg,
                "total_revenue": game.total_revenue,
            }
        )

    top_performers = sorted(performers, key=lambda x: x["daily_revenue"], reverse=True)[:10]
    worst_performers = sorted(performers, key=lambda x: x["daily_revenue"])[:10]

    top_5_games = top_performers[:5]
    bottom_3_games = worst_performers[:3]
    total_revenue_30days = sum(daily_revenue.values())

    # Inventory data
    low_stock_items = InventoryItem.query.filter(
        InventoryItem.stock_quantity <= InventoryItem.minimum_stock
    ).all()

    pending_requests = (
        InventoryRequest.query.filter(
            InventoryRequest.status.in_(["Pending", "Approved"])
        )
        .order_by(InventoryRequest.date_requested.desc())
        .all()
    )

    open_maintenance = (
        MaintenanceRecord.query.filter(
            MaintenanceRecord.status.in_(["Open", "In_Progress"])
        )
        .order_by(MaintenanceRecord.date_reported.desc())
        .all()
    )

    update_monthly_rankings_if_due()

    return render_template(
        "reports.html",
        daily_revenue=daily_revenue,
        top_performers=top_performers,
        worst_performers=worst_performers,
        floor_games_count=len(floor_games),
        top_5_games=top_5_games,
        bottom_3_games=bottom_3_games,
        total_revenue_30days=total_revenue_30days,
        low_stock_items=low_stock_items,
        pending_requests=pending_requests,
        open_maintenance=open_maintenance,
    )


@reports_bp.route("/revenue_reports")
@login_required
@requires_role("manager")
def revenue_reports():
    """Generate revenue reports with time-frame filters."""
    try:
        days = request.args.get("days", 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30

    location_filter = request.args.get("location", "")
    start_date = date.today() - timedelta(days=days)

    # Base query — only floor games with working counters
    query = PlayRecord.query.join(Game).filter(
        PlayRecord.date_recorded >= start_date,
        Game.location == "Floor",
        Game.counter_status == "Working",
    )
    if location_filter and location_filter != "Floor":
        query = query.filter(Game.location == location_filter)

    all_records = query.order_by(PlayRecord.date_recorded.desc()).all()

    games_query = Game.query.join(PlayRecord).filter(
        PlayRecord.date_recorded >= start_date,
        Game.location == "Floor",
        Game.counter_status == "Working",
    )
    if location_filter and location_filter != "Floor":
        games_query = games_query.filter(Game.location == location_filter)
    revenue_games = games_query.distinct().all()

    total_revenue = sum(r.revenue for r in all_records)
    total_plays = sum(r.plays_count for r in all_records)
    avg_daily_revenue = total_revenue / days if days > 0 else 0

    game_revenues: dict[int, dict] = {}
    for record in all_records:
        if record.game.id not in game_revenues:
            game_revenues[record.game.id] = {"game": record.game, "revenue": 0, "plays": 0}
        game_revenues[record.game.id]["revenue"] += record.revenue
        game_revenues[record.game.id]["plays"] += record.plays_count

    top_games = sorted(game_revenues.values(), key=lambda x: x["revenue"], reverse=True)[:10]

    daily_revenue: dict[str, float] = {}
    for record in all_records:
        day_str = record.date_recorded.strftime("%Y-%m-%d")
        daily_revenue[day_str] = daily_revenue.get(day_str, 0) + record.revenue

    locations = db.session.query(Game.location.distinct()).all()

    return render_template(
        "revenue_reports.html",
        all_records=all_records,
        revenue_games=revenue_games,
        top_games=top_games,
        days_filter=days,
        location_filter=location_filter,
        start_date=start_date,
        total_revenue=total_revenue,
        total_plays=total_plays,
        avg_daily_revenue=avg_daily_revenue,
        daily_revenue=daily_revenue,
        locations=[loc[0] for loc in locations],
    )


@reports_bp.route("/graphs")
@login_required
@requires_role("manager")
def graphs():
    """Dedicated graphs page with all visual analytics."""
    all_games = Game.query.all()
    floor_games = Game.query.filter_by(location="Floor", counter_status="Working").all()
    total_games = len(all_games)
    total_plays = sum(g.total_plays for g in floor_games)
    total_revenue = sum(g.total_revenue for g in floor_games)

    thirty_days_ago = date.today() - timedelta(days=30)
    recent_records = (
        PlayRecord.query.join(Game)
        .filter(
            PlayRecord.date_recorded >= thirty_days_ago,
            Game.location == "Floor",
            Game.counter_status == "Working",
        )
        .all()
    )
    daily_revenue: dict = {}
    for record in recent_records:
        day = record.date_recorded
        daily_revenue[day] = daily_revenue.get(day, 0) + record.revenue

    performers = []
    for game in floor_games:
        try:
            date_added = game.date_added
            if date_added.tzinfo is None:
                date_added = date_added.replace(tzinfo=dt.UTC)
            days_active = (datetime.now(dt.UTC) - date_added).days or 1
            daily_revenue_avg = game.total_revenue / days_active if game.total_revenue else 0
            performers.append(
                {"game": game, "daily_revenue": daily_revenue_avg, "total_revenue": game.total_revenue or 0}
            )
        except Exception:
            continue

    top_performers = sorted(performers, key=lambda x: x["daily_revenue"], reverse=True)

    status_distribution = Counter(game.status for game in all_games)
    location_distribution = Counter(game.location for game in all_games)

    return render_template(
        "graphs.html",
        total_games=total_games,
        total_plays=total_plays,
        total_revenue=total_revenue,
        floor_games=floor_games,
        all_games=all_games,
        daily_revenue=daily_revenue,
        top_performers=top_performers,
        status_distribution=status_distribution,
        location_distribution=location_distribution,
    )


@reports_bp.route("/export_report_debug")
@login_required
@requires_role("manager")
def export_report_debug():
    """Simplified PDF report for debugging."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Simple Arcade Report", styles["Title"]))
    story.append(Spacer(1, 12))

    total_games = Game.query.count()
    floor_games = Game.query.filter_by(location="Floor").count()
    total_revenue = sum(g.total_revenue for g in Game.query.all())

    summary_data = [
        ["Metric", "Value"],
        ["Total Games", str(total_games)],
        ["Games on Floor", str(floor_games)],
        ["Total Revenue", f"${total_revenue:.2f}"],
    ]
    story.append(Table(summary_data))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="simple_report.pdf", mimetype="application/pdf")


@reports_bp.route("/export_report")
@login_required
@requires_role("manager")
def export_report():
    """Generate full PDF report with charts for management."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import tempfile

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Arcade Performance Report", styles["Title"]))
    story.append(Spacer(1, 12))

    # Summary stats
    total_games = Game.query.count()
    floor_games_count = Game.query.filter_by(location="Floor").count()
    total_revenue = sum(g.total_revenue for g in Game.query.all())

    summary_data = [
        ["Metric", "Value"],
        ["Total Games", str(total_games)],
        ["Games on Floor", str(floor_games_count)],
        ["Total Revenue", f"${total_revenue:.2f}"],
    ]
    summary_table = Table(summary_data)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 12))

    # Worst performers table
    story.append(Paragraph("Worst Performing Games (Recommended for Replacement)", styles["Heading2"]))

    floor_games = Game.query.filter_by(location="Floor", counter_status="Working").all()
    worst_data = [["Game Name", "Daily Revenue", "Total Revenue", "Days Active"]]

    performers = []
    for game in floor_games:
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue_val = game.total_revenue / days_active
        performers.append((game, daily_revenue_val, days_active))

    performers.sort(key=lambda x: x[1])

    for game, daily_rev, days in performers[:5]:
        worst_data.append([game.name, f"${daily_rev:.2f}", f"${game.total_revenue:.2f}", str(days)])

    worst_table = Table(worst_data)
    worst_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.red),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 12),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    story.append(worst_table)
    story.append(Spacer(1, 20))

    # Charts section
    story.append(Paragraph("Performance Charts", styles["Heading1"]))
    story.append(Spacer(1, 12))

    temp_dir = tempfile.mkdtemp()
    charts_added = 0

    # Chart 1: Daily Revenue Trend
    try:
        thirty_days_ago = date.today() - timedelta(days=30)
        recent_records = (
            PlayRecord.query.join(Game)
            .filter(
                PlayRecord.date_recorded >= thirty_days_ago,
                Game.location == "Floor",
                Game.counter_status == "Working",
            )
            .all()
        )
        daily_rev: dict = {}
        for record in recent_records:
            day = record.date_recorded
            daily_rev[day] = daily_rev.get(day, 0) + record.revenue

        if daily_rev:
            plt.figure(figsize=(10, 6))
            sorted_dates = sorted(daily_rev.keys())
            revenues = [daily_rev[d] for d in sorted_dates]
            plt.plot(sorted_dates, revenues, marker="o", linewidth=2, markersize=4)
            plt.title("Daily Revenue Trend (Last 30 Days)", fontsize=14, fontweight="bold")
            plt.xlabel("Date")
            plt.ylabel("Revenue ($)")
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()

            revenue_chart_path = os.path.join(temp_dir, "revenue_trend.png")
            plt.savefig(revenue_chart_path, dpi=150, bbox_inches="tight")
            plt.close()

            story.append(Paragraph("Daily Revenue Trend", styles["Heading2"]))
            story.append(Image(revenue_chart_path, width=6 * inch, height=3.6 * inch))
            story.append(Spacer(1, 12))
            charts_added += 1
    except Exception as e:
        story.append(Paragraph(f"Daily Revenue Chart: Error - {e}", styles["Normal"]))

    # Chart 2: Top 10 Games by Total Revenue
    try:
        top_performers = sorted(performers, key=lambda x: x[1], reverse=True)[:10]
        if top_performers:
            plt.figure(figsize=(10, 6))
            game_names = [
                p[0].name[:15] + ("..." if len(p[0].name) > 15 else "") for p in top_performers
            ]
            revenues = [p[0].total_revenue for p in top_performers]

            bars = plt.bar(range(len(game_names)), revenues, color="skyblue", edgecolor="navy")
            plt.title("Top 10 Games by Total Revenue", fontsize=14, fontweight="bold")
            plt.xlabel("Games")
            plt.ylabel("Total Revenue ($)")
            plt.xticks(range(len(game_names)), game_names, rotation=45, ha="right")

            for bar, revenue in zip(bars, revenues):
                plt.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + max(revenues) * 0.01,
                    f"${revenue:.0f}",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )

            plt.tight_layout()
            top_games_chart_path = os.path.join(temp_dir, "top_games.png")
            plt.savefig(top_games_chart_path, dpi=150, bbox_inches="tight")
            plt.close()

            story.append(Paragraph("Top Performing Games", styles["Heading2"]))
            story.append(Image(top_games_chart_path, width=6 * inch, height=3.6 * inch))
            story.append(Spacer(1, 12))
            charts_added += 1
    except Exception as e:
        story.append(Paragraph(f"Top Games Chart: Error - {e}", styles["Normal"]))

    # Chart 3: Game Status Distribution
    try:
        all_games = Game.query.all()
        status_distribution = Counter(game.status for game in all_games)
        if status_distribution:
            plt.figure(figsize=(8, 8))
            labels = list(status_distribution.keys())
            sizes = list(status_distribution.values())
            pie_colors = ["#ff9999", "#66b3ff", "#99ff99", "#ffcc99"]

            plt.pie(
                sizes,
                labels=labels,
                autopct="%1.1f%%",
                colors=pie_colors,
                startangle=90,
                textprops={"fontsize": 10},
            )
            plt.title("Game Status Distribution", fontsize=14, fontweight="bold")
            plt.axis("equal")

            status_chart_path = os.path.join(temp_dir, "status_distribution.png")
            plt.savefig(status_chart_path, dpi=150, bbox_inches="tight")
            plt.close()

            story.append(Paragraph("Game Status Distribution", styles["Heading2"]))
            story.append(Image(status_chart_path, width=5 * inch, height=5 * inch))
            charts_added += 1
    except Exception as e:
        story.append(Paragraph(f"Status Chart: Error - {e}", styles["Normal"]))

    if charts_added == 0:
        story.append(Paragraph("Charts could not be generated. Please check server logs.", styles["Normal"]))

    doc.build(story)
    buffer.seek(0)

    # Clean up temporary files
    try:
        import shutil

        shutil.rmtree(temp_dir)
    except Exception:
        pass

    return send_file(buffer, as_attachment=True, download_name="arcade_report.pdf", mimetype="application/pdf")


@reports_bp.route("/export_revenue_report")
@login_required
@requires_role("manager")
def export_revenue_report():
    """Export revenue report as PDF."""
    try:
        days = request.args.get("days", 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30

    location_filter = request.args.get("location", "")
    start_date = date.today() - timedelta(days=days)

    query = PlayRecord.query.join(Game).filter(
        PlayRecord.date_recorded >= start_date,
        Game.location == "Floor",
        Game.counter_status == "Working",
    )

    if location_filter and location_filter != "Floor":
        query = query.filter(Game.location == location_filter)
        title = f"Revenue Report - {location_filter} (Last {days} Days)"
    else:
        title = f"Revenue Report - Floor Games with Working Counters (Last {days} Days)"

    records = query.order_by(PlayRecord.date_recorded.desc()).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(title, styles["Title"]))
    story.append(Spacer(1, 12))

    total_revenue = sum(r.revenue for r in records)
    total_plays = sum(r.plays_count for r in records)
    avg_daily_revenue = total_revenue / days if days > 0 else 0

    summary_data = [
        ["Metric", "Value"],
        ["Total Records", str(len(records))],
        ["Total Revenue", f"${total_revenue:.2f}"],
        ["Total Plays", str(total_plays)],
        ["Avg Daily Revenue", f"${avg_daily_revenue:.2f}"],
    ]
    summary_table = Table(summary_data)
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 14),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Top games table
    if records:
        story.append(Paragraph("Top Performing Games", styles["Heading2"]))

        game_revenues: dict[int, dict] = {}
        for record in records:
            if record.game.id not in game_revenues:
                game_revenues[record.game.id] = {"game": record.game, "revenue": 0, "plays": 0}
            game_revenues[record.game.id]["revenue"] += record.revenue
            game_revenues[record.game.id]["plays"] += record.plays_count

        top_games = sorted(game_revenues.values(), key=lambda x: x["revenue"], reverse=True)[:10]

        revenue_data = [["Game", "Revenue", "Plays", "Avg per Play"]]
        for game_data in top_games:
            avg_per_play = game_data["revenue"] / game_data["plays"] if game_data["plays"] > 0 else 0
            revenue_data.append(
                [
                    game_data["game"].name[:20] + ("..." if len(game_data["game"].name) > 20 else ""),
                    f"${game_data['revenue']:.2f}",
                    str(game_data["plays"]),
                    f"${avg_per_play:.2f}",
                ]
            )

        revenue_table = Table(revenue_data, colWidths=[150, 80, 60, 80])
        revenue_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgreen),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black),
                ]
            )
        )
        story.append(revenue_table)

    doc.build(story)
    buffer.seek(0)

    filename = f"revenue_report_{days}days.pdf"
    if location_filter:
        filename = f"revenue_report_{location_filter}_{days}days.pdf"

    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="application/pdf")


@reports_bp.route("/export_csv")
@login_required
@requires_role("manager")
def export_csv():
    """Export game data to CSV."""
    games = Game.query.all()
    data = []

    for game in games:
        date_added = game.date_added
        if date_added.tzinfo is None:
            date_added = date_added.replace(tzinfo=dt.UTC)
        days_active = (datetime.now(dt.UTC) - date_added).days or 1
        daily_revenue = game.total_revenue / days_active

        data.append(
            {
                "Game Name": game.name,
                "Manufacturer": game.manufacturer,
                "Location": game.location,
                "Status": game.status,
                "Total Plays": game.total_plays,
                "Total Revenue": game.total_revenue,
                "Daily Revenue": round(daily_revenue, 2),
                "Days Active": days_active,
                "Top 5 Count": game.times_in_top_5,
                "Top 10 Count": game.times_in_top_10,
            }
        )

    df = pd.DataFrame(data)
    output = io.StringIO()
    df.to_csv(output, index=False)
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=arcade_data.csv"
    response.headers["Content-type"] = "text/csv"
    return response
