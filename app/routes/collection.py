"""The collection round (feature step 3): read every coin meter on the floor in one walk.

See app/services/collection.py for what a round is and what gets flagged.
"""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import login_required

from app.extensions import db
from app.models import Game
from app.services import collection as rounds
from app.services.upkeep import raise_due
from app.utils.decorators import requires_role

collection_bp = Blueprint("collection", __name__, url_prefix="/round")

# While this holds today's date, scanning a floor machine's label opens its meter entry
# (games.resolve_barcode). Yesterday's date means no round is open.
SESSION_KEY = "collection_round"


def round_open() -> bool:
    return session.get(SESSION_KEY) == rounds.local_today().isoformat()


def _summary(stops):
    read = [s for s in stops if s.done]
    readable = [s for s in stops if s.meter_ok or s.done]
    return {
        "read": len(read), "readable": len(readable),
        "plays": sum(s.read_today.plays_count for s in read),
        "value": sum(s.read_today.revenue for s in read),
        "flagged": sum(1 for s in read if s.flags),
        "broken": sum(1 for s in stops if not s.meter_ok and not s.done),
    }


@collection_bp.route("/")
@login_required
@requires_role("operator")
def overview():
    session[SESSION_KEY] = rounds.local_today().isoformat()
    stops = rounds.plan()
    return render_template("round.html", stops=stops, summary=_summary(stops),
                           next_stop=rounds.next_stop(stops))


@collection_bp.route("/end", methods=["POST"])
@login_required
@requires_role("operator")
def end():
    session.pop(SESSION_KEY, None)
    flash("Round closed. Scanning a label opens the machine's page again.", "info")
    return redirect(url_for("dashboard.home"))


@collection_bp.route("/<int:game_id>", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def stop(game_id):
    from app.services.machine_edit import parse_reading, record_reading, set_baseline

    game = db.get_or_404(Game, game_id)
    session[SESSION_KEY] = rounds.local_today().isoformat()
    stops = rounds.plan()
    here = next((s for s in stops if s.game.id == game.id), None)
    if here is None:
        flash(f'"{game.name}" isn\'t on the floor, so it isn\'t on the round.', "warning")
        return redirect(url_for("games.game_detail", game_id=game.id))
    position = stops.index(here) + 1
    after = rounds.next_stop(stops, game.id)
    page = {"stop": here, "position": position, "total": len(stops), "after": after,
            "values": {}, "errors": {}, "pending": []}

    if request.method == "GET" or here.done or not here.meter_ok:
        if request.method == "POST":
            flash(f'"{game.name}" was already read today.' if here.done
                  else f'"{game.name}"\'s meter is marked broken.', "warning")
        return render_template("round_stop.html", **page)

    form = {"coin_count": request.form.get("coin_count"), "notes": request.form.get("notes"),
            "date": rounds.local_today().isoformat()}
    reading, errors = parse_reading(form, here.last_count)
    if errors:
        return render_template("round_stop.html", **{**page, "values": request.form,
                                                     "errors": errors}), 400

    note = reading.notes or "Collection round"
    if here.first_reading:
        set_baseline(game, reading.coin_count, f"First reading (collection round). {note}"
                     if reading.notes else "First reading (collection round)")
        db.session.commit()
        flash(f'{game.name}: starting point set at {reading.coin_count:,}. Plays count from '
              "the next round.", "success")
        return _onward(after)

    plays = reading.coin_count - here.last_count
    flags = rounds.assess(here.before, plays, rounds.local_today())
    high = [f for f in flags if f.kind == "high"]
    if high and request.form.get("confirm_high") != "1":
        return render_template("round_stop.html", **{**page, "values": request.form,
                                                     "pending": high})

    reading.notes = note
    record = record_reading(game, reading, here.last_count)
    db.session.commit()
    flash(f"{game.name}: {record.plays_count:,} plays (${record.revenue:,.2f}).", "success")
    for f in flags:
        if f.kind == "high":
            continue        # already shown and confirmed; the round's list still marks it
        flash(f"{game.name}: {f.text}", "warning")
    for order in raise_due([game]):         # new plays may bring maintenance due (step 5)
        flash(f"{game.name} is due for maintenance: work order #{order.id} raised.", "info")
    return _onward(after)


def _onward(after):
    if after is None:
        flash("That's every machine on the round.", "success")
        return redirect(url_for("collection.overview"))
    return redirect(url_for("collection.stop", game_id=after.game.id))
