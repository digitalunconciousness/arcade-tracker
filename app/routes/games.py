"""Games blueprint — CRUD operations, play recording, bulk updates, export."""

import io
import os
import json
import uuid
import datetime as dt
from datetime import datetime, date

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_required
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import Game, PlayRecord, MaintenanceRecord
from app.utils.decorators import requires_role
from app.utils.helpers import (
    allowed_file,
    generate_unique_barcode,
    import_games_from_roster,
)

games_bp = Blueprint("games", __name__)


@games_bp.route("/games")
@login_required
def games_list():
    search = request.args.get("search", "")
    location_filter = request.args.get("location", "")
    status_filter = request.args.get("status", "")

    query = Game.query

    if search:
        query = query.filter(Game.name.contains(search))
    if location_filter:
        query = query.filter_by(location=location_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)

    # Get all games sorted alphabetically
    games = query.order_by(Game.name.asc()).all()

    # Separate into floor and warehouse games
    floor_games = [g for g in games if g.location == "Floor"]
    warehouse_games = [g for g in games if g.location == "Warehouse"]

    # Get games with open maintenance requests
    games_with_open_maintenance = set(
        row[0]
        for row in db.session.query(MaintenanceRecord.game_id)
        .filter(MaintenanceRecord.status.in_(["Open", "In_Progress"]))
        .distinct()
        .all()
    )

    # Add maintenance indicator to games
    for game in games:
        game.has_open_maintenance = game.id in games_with_open_maintenance

    # Get unique values for filter dropdowns
    locations = db.session.query(Game.location.distinct()).all()
    statuses = db.session.query(Game.status.distinct()).all()

    return render_template(
        "games_list.html",
        games=games,
        floor_games=floor_games,
        warehouse_games=warehouse_games,
        search=search,
        location_filter=location_filter,
        status_filter=status_filter,
        locations=[loc[0] for loc in locations],
        statuses=[s[0] for s in statuses],
    )


@games_bp.route("/add_game", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def add_game():
    if request.method == "POST":
        name = request.form["name"]
        manufacturer = request.form.get("manufacturer", "")
        year = request.form.get("year")
        genre = request.form.get("genre", "")
        location = request.form.get("location", "Warehouse")
        status = request.form.get("status", "Working")
        coins_per_play_str = request.form.get("coins_per_play", "0.25")
        if coins_per_play_str and coins_per_play_str.strip():
            coins_per_play = float(coins_per_play_str)
        else:
            coins_per_play = 0.25
        counter_status = request.form.get("counter_status", "Working")
        counter_notes = request.form.get("counter_notes", "")
        notes = request.form.get("notes", "")

        # Convert year to int if provided
        if year and year.strip():
            try:
                year = int(year)
            except ValueError:
                year = None
        else:
            year = None

        # Handle image upload
        image_filename = None
        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename != "" and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                name_part, ext = os.path.splitext(filename)
                filename = f"{name_part}_{uuid.uuid4().hex[:8]}{ext}"

                os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)

                filepath = os.path.join(
                    current_app.config["UPLOAD_FOLDER"], filename
                )
                file.save(filepath)
                image_filename = filename

        # Assign a stable barcode/QR slug from the name
        taken_barcodes = {b for (b,) in db.session.query(Game.barcode).all() if b}
        barcode = generate_unique_barcode(name, taken_barcodes)

        game = Game(
            name=name,
            barcode=barcode,
            manufacturer=manufacturer,
            year=year,
            genre=genre,
            location=location,
            status=status,
            coins_per_play=coins_per_play,
            counter_status=counter_status,
            counter_notes=counter_notes,
            notes=notes,
            image_filename=image_filename,
        )

        db.session.add(game)
        db.session.commit()

        # Handle initial coin count if provided and counter is working
        initial_coin_count = request.form.get("initial_coin_count")
        if (
            initial_coin_count
            and initial_coin_count.strip()
            and counter_status == "Working"
        ):
            try:
                coin_count = int(initial_coin_count)
                if coin_count > 0:
                    initial_record = PlayRecord(
                        game_id=game.id,
                        coin_count=coin_count,
                        plays_count=0,
                        revenue=0.0,
                        date_recorded=date.today(),
                        notes="Initial baseline coin count",
                    )
                    db.session.add(initial_record)
                    db.session.commit()
            except (ValueError, TypeError):
                pass

        success_msg = f'Game "{game.name}" added successfully!'
        if initial_coin_count and initial_coin_count.strip():
            try:
                coin_count = int(initial_coin_count)
                if coin_count > 0:
                    success_msg += f" (Baseline: {coin_count} coins)"
            except (ValueError, TypeError):
                pass
        flash(success_msg, "success")
        return redirect(url_for("games.games_list"))

    return render_template("add_game.html")


@games_bp.route("/game/<int:game_id>")
@login_required
def game_detail(game_id):
    game = Game.query.get_or_404(game_id)
    recent_records = (
        PlayRecord.query.filter_by(game_id=game_id)
        .order_by(PlayRecord.date_recorded.desc())
        .limit(10)
        .all()
    )
    maintenance_records = (
        MaintenanceRecord.query.filter_by(game_id=game_id)
        .order_by(MaintenanceRecord.date_reported.desc())
        .all()
    )

    # Check if there are no play records (can add baseline)
    all_records_count = PlayRecord.query.filter_by(game_id=game_id).count()
    can_add_baseline = all_records_count == 0

    return render_template(
        "game_detail.html",
        game=game,
        recent_records=recent_records,
        maintenance_records=maintenance_records,
        can_add_baseline=can_add_baseline,
    )


@games_bp.route("/edit_game/<int:game_id>", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def edit_game(game_id):
    game = Game.query.get_or_404(game_id)

    # Check if game has any play records beyond baseline
    all_records = PlayRecord.query.filter_by(game_id=game_id).all()
    has_play_records = len(all_records) > 1 or (
        len(all_records) == 1 and all_records[0].plays_count > 0
    )

    if request.method == "POST":
        game.name = request.form["name"]
        game.manufacturer = request.form.get("manufacturer", "")
        year = request.form.get("year")
        game.year = int(year) if year and year.strip() else None
        game.genre = request.form.get("genre", "")
        game.location = request.form.get("location", "Warehouse")
        game.floor_position = request.form.get("floor_position", "")
        game.warehouse_section = request.form.get("warehouse_section", "")
        game.status = request.form.get("status", "Working")
        coins_per_play_str = request.form.get("coins_per_play", "0.25")
        if coins_per_play_str and coins_per_play_str.strip():
            game.coins_per_play = float(coins_per_play_str)
        else:
            game.coins_per_play = 0.25
        game.counter_status = request.form.get("counter_status", "Working")
        game.counter_notes = request.form.get("counter_notes", "")
        game.notes = request.form.get("notes", "")

        # Handle new image upload
        if "image" in request.files:
            file = request.files["image"]
            if file and file.filename != "" and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                name_part, ext = os.path.splitext(filename)
                filename = f"{name_part}_{uuid.uuid4().hex[:8]}{ext}"

                os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)

                filepath = os.path.join(
                    current_app.config["UPLOAD_FOLDER"], filename
                )
                file.save(filepath)

                # Remove old image if it exists
                if game.image_filename:
                    old_path = os.path.join(
                        current_app.config["UPLOAD_FOLDER"],
                        game.image_filename,
                    )
                    if os.path.exists(old_path):
                        os.remove(old_path)

                game.image_filename = filename

        # Handle initial coin count if provided and no actual play records exist
        if not has_play_records:
            initial_coin_count = request.form.get("initial_coin_count")
            if initial_coin_count and initial_coin_count.strip():
                try:
                    coin_count = int(initial_coin_count)
                    if coin_count >= 0:
                        existing_baseline = None
                        if (
                            len(all_records) == 1
                            and all_records[0].plays_count == 0
                        ):
                            existing_baseline = all_records[0]

                        if existing_baseline:
                            existing_baseline.coin_count = coin_count
                            existing_baseline.date_recorded = date.today()
                            existing_baseline.notes = (
                                "Updated baseline coin count (via edit)"
                            )
                        else:
                            initial_record = PlayRecord(
                                game_id=game_id,
                                coin_count=coin_count,
                                plays_count=0,
                                revenue=0.0,
                                date_recorded=date.today(),
                                notes="Initial baseline coin count (added via edit)",
                            )
                            db.session.add(initial_record)
                except (ValueError, TypeError):
                    pass

        db.session.commit()

        success_msg = f'Game "{game.name}" updated successfully!'
        if not has_play_records:
            initial_coin_count = request.form.get("initial_coin_count")
            if initial_coin_count and initial_coin_count.strip():
                try:
                    coin_count = int(initial_coin_count)
                    if coin_count >= 0:
                        action = (
                            "Updated"
                            if (
                                len(all_records) == 1
                                and all_records[0].plays_count == 0
                            )
                            else "Set"
                        )
                        success_msg += (
                            f" ({action} baseline: {coin_count} coins)"
                        )
                except (ValueError, TypeError):
                    pass

        flash(success_msg, "success")
        return redirect(url_for("games.game_detail", game_id=game_id))

    return render_template(
        "edit_game.html", game=game, has_play_records=has_play_records
    )


@games_bp.route("/record_plays/<int:game_id>", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def record_plays(game_id):
    game = Game.query.get_or_404(game_id)

    # Check if counter is working
    if game.counter_status != "Working":
        flash(
            f'Cannot record plays for "{game.name}" - Counter status: '
            f'{game.counter_status.replace("_", " ")}',
            "error",
        )
        return redirect(url_for("games.game_detail", game_id=game_id))

    # Get the most recent coin count for this game
    last_record = (
        PlayRecord.query.filter_by(game_id=game_id)
        .order_by(PlayRecord.date_recorded.desc())
        .first()
    )
    last_coin_count = last_record.coin_count if last_record else 0

    if request.method == "POST":
        try:
            current_coin_count = int(request.form["coin_count"])
        except (ValueError, KeyError):
            flash("Error: Invalid coin count value", "error")
            return render_template(
                "record_plays.html", game=game, last_coin_count=last_coin_count
            )
        record_date = datetime.strptime(
            request.form["date"], "%Y-%m-%d"
        ).date()
        notes = request.form.get("notes", "")

        # Validate coin count is not less than previous
        if current_coin_count < last_coin_count:
            flash(
                f"Error: Coin count ({current_coin_count}) cannot be less than "
                f"the previous reading ({last_coin_count})",
                "error",
            )
            return render_template(
                "record_plays.html", game=game, last_coin_count=last_coin_count
            )

        # Calculate plays from difference
        new_plays = current_coin_count - last_coin_count

        # Calculate revenue
        revenue = new_plays * game.coins_per_play

        # Create play record
        play_record = PlayRecord(
            game_id=game_id,
            coin_count=current_coin_count,
            plays_count=new_plays,
            revenue=revenue,
            date_recorded=record_date,
            notes=notes,
        )
        db.session.add(play_record)

        # Update totals
        game.total_plays += new_plays
        game.total_revenue += revenue
        db.session.commit()

        flash(
            f'Recorded {new_plays} plays (${revenue:.2f}) for "{game.name}" '
            f"- Coin count: {current_coin_count}",
            "success",
        )
        return redirect(url_for("games.game_detail", game_id=game_id))

    return render_template(
        "record_plays.html", game=game, last_coin_count=last_coin_count
    )


@games_bp.route("/delete_play_record/<int:record_id>", methods=["POST"])
@login_required
@requires_role("manager")
def delete_play_record(record_id):
    record = PlayRecord.query.get_or_404(record_id)
    game_id = record.game_id
    game = Game.query.get_or_404(game_id)

    # Store values before deletion
    plays_to_subtract = record.plays_count
    revenue_to_subtract = record.revenue

    # Update game totals
    game.total_plays -= plays_to_subtract
    game.total_revenue -= revenue_to_subtract

    # Ensure totals don't go negative
    if game.total_plays < 0:
        game.total_plays = 0
    if game.total_revenue < 0:
        game.total_revenue = 0.0

    # Delete the record
    db.session.delete(record)
    db.session.commit()

    flash("Play record deleted successfully", "success")
    return redirect(url_for("games.game_detail", game_id=game_id))


@games_bp.route("/add_baseline/<int:game_id>", methods=["POST"])
@login_required
@requires_role("operator")
def add_baseline(game_id):
    game = Game.query.get_or_404(game_id)

    # Check if there are already play records
    existing_records = PlayRecord.query.filter_by(game_id=game_id).count()
    if existing_records > 0:
        flash("Cannot add baseline - play records already exist", "error")
        return redirect(url_for("games.game_detail", game_id=game_id))

    # Get coin count from form
    try:
        coin_count = int(request.form.get("baseline_coin_count", 0))
        if coin_count < 0:
            flash("Baseline coin count cannot be negative", "error")
            return redirect(url_for("games.game_detail", game_id=game_id))
    except ValueError:
        flash("Invalid coin count", "error")
        return redirect(url_for("games.game_detail", game_id=game_id))

    # Create baseline record
    baseline_record = PlayRecord(
        game_id=game_id,
        coin_count=coin_count,
        plays_count=0,
        revenue=0.0,
        date_recorded=date.today(),
        notes="Baseline coin count",
    )

    db.session.add(baseline_record)
    db.session.commit()

    flash(f"Baseline set to {coin_count} coins", "success")
    return redirect(url_for("games.game_detail", game_id=game_id))


@games_bp.route("/delete_game/<int:game_id>", methods=["POST"])
@login_required
@requires_role("admin")
def delete_game(game_id):
    """Delete a game and all associated records."""
    game = Game.query.get_or_404(game_id)

    try:
        PlayRecord.query.filter_by(game_id=game_id).delete()
        MaintenanceRecord.query.filter_by(game_id=game_id).delete()

        # Delete the game image if it exists
        if game.image_filename:
            image_path = os.path.join(
                current_app.config["UPLOAD_FOLDER"], game.image_filename
            )
            if os.path.exists(image_path):
                os.remove(image_path)

        game_name = game.name
        db.session.delete(game)
        db.session.commit()

        flash(
            f'Game "{game_name}" and all associated records have been '
            f"deleted successfully.",
            "success",
        )
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting game: {str(e)}", "error")

    return redirect(url_for("games.games_list"))


@games_bp.route("/bulk_update_games", methods=["POST"])
@login_required
@requires_role("manager")
def bulk_update_games():
    """Bulk update multiple games at once."""
    action = request.form.get("action")
    game_ids = request.form.getlist("game_ids")

    if not game_ids:
        flash("No games selected", "error")
        return redirect(url_for("games.games_list"))

    games = Game.query.filter(Game.id.in_(game_ids)).all()
    count = len(games)

    try:
        if action == "move_to_floor":
            for game in games:
                game.location = "Floor"
            flash(f"Moved {count} game(s) to Floor", "success")

        elif action == "move_to_warehouse":
            for game in games:
                game.location = "Warehouse"
            flash(f"Moved {count} game(s) to Warehouse", "success")

        elif action == "set_working":
            for game in games:
                game.status = "Working"
            flash(f"Set {count} game(s) to Working status", "success")

        elif action == "set_not_working":
            for game in games:
                game.status = "Not_Working"
            flash(f"Set {count} game(s) to Not Working status", "success")

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash(f"Error updating games: {str(e)}", "error")

    return redirect(url_for("games.games_list"))


@games_bp.route("/export_selected_games")
@login_required
@requires_role("manager")
def export_selected_games():
    """Export selected games to CSV."""
    game_ids = request.args.getlist("game_ids")

    if not game_ids:
        flash("No games selected", "error")
        return redirect(url_for("games.games_list"))

    games = Game.query.filter(Game.id.in_(game_ids)).all()
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
            }
        )

    import csv

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "Game Name", "Manufacturer", "Location", "Status",
        "Total Plays", "Total Revenue", "Daily Revenue", "Days Active",
    ])
    writer.writeheader()
    writer.writerows(data)
    output.seek(0)

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = (
        f"attachment; filename=selected_games_{len(games)}.csv"
    )
    response.headers["Content-type"] = "text/csv"

    return response


@games_bp.route("/import_games", methods=["GET", "POST"])
@login_required
@requires_role("manager")
def import_games():
    """Bulk-import games from an uploaded barcade-roster JSON file.

    Accepts the ``catbox-barcade-roster.json`` structure (``video_games`` /
    ``pinball`` / ``retired`` arrays + ``meta.platforms``). Idempotent: existing
    games (matched by name) are skipped, so re-uploading never duplicates.
    """
    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            flash("No file selected.", "error")
            return redirect(url_for("games.import_games"))

        try:
            data = json.load(file.stream)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            flash(f"Not valid JSON: {exc}", "error")
            return redirect(url_for("games.import_games"))

        if not isinstance(data, dict) or not any(
            k in data for k in ("video_games", "pinball", "retired")
        ):
            flash(
                "JSON is missing the expected 'video_games' / 'pinball' / "
                "'retired' arrays.",
                "error",
            )
            return redirect(url_for("games.import_games"))

        try:
            result = import_games_from_roster(data)
            db.session.commit()
        except Exception as exc:  # noqa: BLE001
            db.session.rollback()
            flash(f"Import failed: {exc}", "error")
            return redirect(url_for("games.import_games"))

        msg = (
            f"Import complete: {result['added']} added, "
            f"{result['skipped']} skipped (already present)."
        )
        flash(msg, "success" if not result["errors"] else "warning")
        for err in result["errors"][:10]:
            flash(err, "error")
        return redirect(url_for("games.games_list"))

    return render_template("import_games.html")


@games_bp.route("/scan")
@login_required
def scan():
    """Kiosk page: a focused input a USB HID barcode scanner types into."""
    return render_template("scan.html")


@games_bp.route("/g/<code>")
@login_required
def resolve_barcode(code):
    """Resolve a scanned barcode/QR payload to a game's maintenance page.

    Matches on the ``barcode`` slug first, then falls back to a numeric id so
    labels that encode the raw database id still resolve.
    """
    game = Game.query.filter_by(barcode=code).first()
    if game is None and code.isdigit():
        game = Game.query.get(int(code))
    if game is None:
        flash(f"No machine found for scanned code '{code}'.", "error")
        return redirect(url_for("games.scan"))
    return redirect(url_for("maintenance.game_maintenance", game_id=game.id))


@games_bp.route("/game/<int:game_id>/label")
@login_required
def game_label(game_id):
    """Printable QR label for a game, encoding a link to its maintenance page."""
    import segno

    game = Game.query.get_or_404(game_id)

    # Backfill a barcode on the fly for any legacy row that lacks one.
    if not game.barcode:
        taken = {b for (b,) in db.session.query(Game.barcode).all() if b}
        game.barcode = generate_unique_barcode(game.name, taken)
        db.session.commit()

    base_url = (current_app.config.get("BASE_URL") or request.host_url).rstrip("/")
    label_url = f"{base_url}/g/{game.barcode}"
    qr_data_uri = segno.make(label_url, error="m").svg_data_uri(scale=6, border=2)

    return render_template(
        "game_label.html",
        game=game,
        label_url=label_url,
        qr_data_uri=qr_data_uri,
    )
