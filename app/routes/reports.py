"""Reports blueprint — revenue reports, graphs, PDF/CSV export."""

import datetime as dt
import io
import os
from collections import Counter
from datetime import date, datetime, timedelta

from flask import (
    Blueprint,
    current_app,
    make_response,
    render_template,
    request,
    send_file,
)
from flask_login import login_required

from app.extensions import db
from app.models import (
    Game,
    InventoryItem,
    InventoryRequest,
    MaintenanceRecord,
    PlayRecord,
)
from app.services.branding import pdf_masthead
from app.services.rankings import update_monthly_rankings_if_due
from app.services.revenue import location_options, scope_label, scoped, series
from app.ui import status_label, status_tone
from app.utils.decorators import requires_role

reports_bp = Blueprint("reports", __name__)


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

    # Plays first, token value second (wording pass, 2026-10-26).
    daily_plays: dict[str, int] = {}
    for record in recent_records:
        day = record.date_recorded.strftime("%Y-%m-%d")
        daily_plays[day] = daily_plays.get(day, 0) + (record.plays_count or 0)
    total_plays_30days = sum(daily_plays.values())
    total_value_30days = sum(r.revenue or 0.0 for r in recent_records)

    # Ranked by plays per working day, the rotation planner's measure (app/services/popularity.py).
    from app.services.popularity import WINDOW_DAYS, floor_ranking

    ranked = floor_ranking()
    performers = [{"game": m.game, "plays_per_day": m.rate.per_day,
                   "value_per_day": m.rate.value_per_day} for m in ranked]
    top_performers = performers[:10]
    worst_performers = list(reversed(performers))[:10]
    top_5_games = top_performers[:5]
    bottom_3_games = worst_performers[:3]
    floor_games = Game.query.filter_by(location="Floor", counter_status="Working").all()

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

    update_monthly_rankings_if_due()  # writes on GET (F-14), as before

    return render_template(
        "reports.html",
        daily_plays=daily_plays,
        top_performers=top_performers,
        worst_performers=worst_performers,
        floor_games_count=len(floor_games),
        top_5_games=top_5_games,
        bottom_3_games=bottom_3_games,
        total_plays_30days=total_plays_30days,
        total_value_30days=total_value_30days,
        window_days=WINDOW_DAYS,
        low_stock_items=low_stock_items,
        pending_requests=pending_requests,
        open_maintenance=open_maintenance,
        daily_chart=series(daily_plays),
        games_chart={"labels": [p["game"].name for p in top_performers],
                     "values": [round(p["plays_per_day"], 1) for p in top_performers]},
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

    query = scoped(PlayRecord.query.join(Game).filter(PlayRecord.date_recorded >= start_date),
                   location_filter)
    all_records = query.order_by(PlayRecord.date_recorded.desc()).all()

    games_query = scoped(Game.query.join(PlayRecord).filter(PlayRecord.date_recorded >= start_date),
                         location_filter)
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

    # Most played first; token value second (wording pass, 2026-10-26).
    top_games = sorted(game_revenues.values(), key=lambda x: (x["plays"], x["revenue"]),
                       reverse=True)[:10]

    daily_plays: dict[str, int] = {}
    for record in all_records:
        day_str = record.date_recorded.strftime("%Y-%m-%d")
        daily_plays[day_str] = daily_plays.get(day_str, 0) + (record.plays_count or 0)

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
        avg_daily_plays=total_plays / days if days > 0 else 0,
        daily_chart=series(daily_plays),
        location_options=location_options(loc[0] for loc in locations),
        scope=scope_label(location_filter),
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
    daily_plays: dict = {}
    for record in recent_records:
        day = record.date_recorded
        daily_plays[day] = daily_plays.get(day, 0) + (record.plays_count or 0)

    # Most played first, by plays per working day (app/services/popularity.py).
    from app.services.popularity import floor_ranking

    top_performers = floor_ranking()

    status_distribution = Counter(game.status for game in all_games)
    location_distribution = Counter(game.location for game in all_games)

    return render_template(
        "graphs.html",
        total_games=total_games,
        total_plays=total_plays,
        total_revenue=total_revenue,
        floor_games=floor_games,
        all_games=all_games,
        daily_plays=daily_plays,
        top_performers=top_performers,
        status_distribution=status_distribution,
        location_distribution=location_distribution,
        # JSON islands, so a machine name with an apostrophe can't break the script.
        daily_chart=series(daily_plays),
        top_chart={"labels": [m.game.name for m in top_performers[:8]],
                   "values": [round(m.rate.per_day, 1) for m in top_performers[:8]]},
        status_chart={"labels": [status_label(k) for k in status_distribution],
                      "values": list(status_distribution.values()),
                      "tones": [status_tone(k) for k in status_distribution]},
        location_chart={"labels": [k or "Unknown" for k in location_distribution],
                        "values": list(location_distribution.values())},
    )


@reports_bp.route("/export_report_debug")
@login_required
@requires_role("manager")
def export_report_debug():
    """Simplified PDF report for debugging."""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.extend(pdf_masthead(styles))   # the arcade's logo (Admin, Branding)
    story.append(Paragraph("Simple Arcade Report", styles["Title"]))
    story.append(Spacer(1, 12))

    total_games = Game.query.count()
    floor_games = Game.query.filter_by(location="Floor").count()
    every_game = Game.query.all()
    total_plays = sum(g.total_plays or 0 for g in every_game)
    total_revenue = sum(g.total_revenue or 0 for g in every_game)

    summary_data = [
        ["Metric", "Value"],
        ["Total Games", str(total_games)],
        ["Games on Floor", str(floor_games)],
        ["Total Plays", f"{total_plays:,}"],
        ["Token Value", f"${total_revenue:,.2f}"],
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
    import tempfile

    import matplotlib.pyplot as plt
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

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.extend(pdf_masthead(styles))   # the arcade's logo (Admin, Branding)
    story.append(Paragraph("Arcade Performance Report", styles["Title"]))
    story.append(Spacer(1, 12))

    # Summary stats
    total_games = Game.query.count()
    floor_games_count = Game.query.filter_by(location="Floor").count()
    every_game = Game.query.all()
    total_plays = sum(g.total_plays or 0 for g in every_game)
    total_revenue = sum(g.total_revenue or 0 for g in every_game)

    # Plays first, token value second (wording pass, 2026-10-26).
    summary_data = [
        ["Metric", "Value"],
        ["Total Games", str(total_games)],
        ["Games on Floor", str(floor_games_count)],
        ["Total Plays", f"{total_plays:,}"],
        ["Token Value", f"${total_revenue:,.2f}"],
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

    # Least played, by plays per working day (app/services/popularity.py)
    from app.services.popularity import WINDOW_DAYS, floor_ranking

    ranked = floor_ranking()
    story.append(Paragraph(f"Least Played Games, last {WINDOW_DAYS} days (candidates to swap out)",
                           styles["Heading2"]))
    worst_data = [["Game Name", "Plays per Day", "Token Value per Day", "Days Counted"]]
    for m in list(reversed(ranked))[:5]:
        worst_data.append([m.game.name, f"{m.rate.per_day:.1f}", f"${m.rate.value_per_day:.2f}",
                           str(m.rate.days)])

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

    # Chart 1: Daily plays
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
        daily_plays: dict = {}
        for record in recent_records:
            day = record.date_recorded
            daily_plays[day] = daily_plays.get(day, 0) + (record.plays_count or 0)

        if daily_plays:
            plt.figure(figsize=(10, 6))
            sorted_dates = sorted(daily_plays.keys())
            plays = [daily_plays[d] for d in sorted_dates]
            plt.plot(sorted_dates, plays, marker="o", linewidth=2, markersize=4)
            plt.title("Plays by Day (Last 30 Days)", fontsize=14, fontweight="bold")
            plt.xlabel("Date")
            plt.ylabel("Plays")
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            plt.tight_layout()

            revenue_chart_path = os.path.join(temp_dir, "revenue_trend.png")
            plt.savefig(revenue_chart_path, dpi=150, bbox_inches="tight")
            plt.close()

            story.append(Paragraph("Plays by Day", styles["Heading2"]))
            story.append(Image(revenue_chart_path, width=6 * inch, height=3.6 * inch))
            story.append(Spacer(1, 12))
            charts_added += 1
    except Exception:
        current_app.logger.exception("PDF report: daily plays chart failed")
        story.append(Paragraph("Plays by Day Chart: could not be drawn (see the server log).",
                               styles["Normal"]))

    # Chart 2: the 10 most played, per working day
    try:
        top_performers = ranked[:10]
        if top_performers:
            plt.figure(figsize=(10, 6))
            game_names = [
                m.game.name[:15] + ("..." if len(m.game.name) > 15 else "") for m in top_performers
            ]
            per_day = [m.rate.per_day for m in top_performers]

            bars = plt.bar(range(len(game_names)), per_day, color="skyblue", edgecolor="navy")
            plt.title("Top 10 Games by Plays per Working Day", fontsize=14, fontweight="bold")
            plt.xlabel("Games")
            plt.ylabel("Plays per day")
            plt.xticks(range(len(game_names)), game_names, rotation=45, ha="right")

            for bar, value in zip(bars, per_day):
                plt.text(
                    bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + max(per_day) * 0.01,
                    f"{value:.1f}",
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
    except Exception:
        current_app.logger.exception("PDF report: top games chart failed")
        story.append(Paragraph("Top Games Chart: could not be drawn (see the server log).",
                               styles["Normal"]))

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
    except Exception:
        current_app.logger.exception("PDF report: status chart failed")
        story.append(Paragraph("Status Chart: could not be drawn (see the server log).",
                               styles["Normal"]))

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
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    try:
        days = request.args.get("days", 30, type=int)
        if days is None or days <= 0:
            days = 30
    except (ValueError, TypeError):
        days = 30

    location_filter = request.args.get("location", "")
    start_date = date.today() - timedelta(days=days)

    query = scoped(PlayRecord.query.join(Game).filter(PlayRecord.date_recorded >= start_date),
                   location_filter)
    # The location comes from the query string, and ReportLab reads markup in a Paragraph.
    from xml.sax.saxutils import escape
    title = escape(f"Plays and Token Value - {scope_label(location_filter)}, working counters "
                   f"(Last {days} Days)")

    records = query.order_by(PlayRecord.date_recorded.desc()).all()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.extend(pdf_masthead(styles))   # the arcade's logo (Admin, Branding)
    story.append(Paragraph(title, styles["Title"]))
    story.append(Spacer(1, 12))

    total_revenue = sum(r.revenue for r in records)
    total_plays = sum(r.plays_count for r in records)
    avg_daily_revenue = total_revenue / days if days > 0 else 0

    summary_data = [
        ["Metric", "Value"],
        ["Total Records", str(len(records))],
        ["Total Plays", f"{total_plays:,}"],
        ["Plays per Day", f"{total_plays / days if days > 0 else 0:,.1f}"],
        ["Token Value", f"${total_revenue:,.2f}"],
        ["Token Value per Day", f"${avg_daily_revenue:,.2f}"],
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
        story.append(Paragraph("Most Played Games", styles["Heading2"]))

        game_revenues: dict[int, dict] = {}
        for record in records:
            if record.game.id not in game_revenues:
                game_revenues[record.game.id] = {"game": record.game, "revenue": 0, "plays": 0}
            game_revenues[record.game.id]["revenue"] += record.revenue
            game_revenues[record.game.id]["plays"] += record.plays_count

        top_games = sorted(game_revenues.values(), key=lambda x: (x["plays"], x["revenue"]),
                           reverse=True)[:10]

        revenue_data = [["Game", "Plays", "Token Value", "Token Value per Play"]]
        for game_data in top_games:
            avg_per_play = game_data["revenue"] / game_data["plays"] if game_data["plays"] > 0 else 0
            revenue_data.append(
                [
                    game_data["game"].name[:20] + ("..." if len(game_data["game"].name) > 20 else ""),
                    f"{game_data['plays']:,}",
                    f"${game_data['revenue']:.2f}",
                    f"${avg_per_play:.2f}",
                ]
            )

        revenue_table = Table(revenue_data, colWidths=[150, 60, 80, 110])
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

    filename = f"plays_report_{days}days.pdf"
    if location_filter:
        filename = f"plays_report_{location_filter}_{days}days.pdf"

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

    import csv

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "Game Name", "Manufacturer", "Location", "Status",
        "Total Plays", "Total Revenue", "Daily Revenue", "Days Active",
        "Top 5 Count", "Top 10 Count",
    ])
    writer.writeheader()
    from app.utils.helpers import csv_safe

    writer.writerows({k: csv_safe(v) for k, v in row.items()} for row in data)
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=arcade_data.csv"
    response.headers["Content-type"] = "text/csv"
    return response
