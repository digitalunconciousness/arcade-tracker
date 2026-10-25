"""The rotation planner (feature step 4). See app/services/rotation.py for the numbers."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_required

from app.extensions import db
from app.models import Game
from app.services import rotation as planner
from app.utils.decorators import requires_role

rotation_bp = Blueprint("rotation", __name__, url_prefix="/rotation")


@rotation_bp.route("/")
@login_required
@requires_role("manager")
def overview():
    options = planner.Options.from_args(request.args)
    return render_template("rotation.html", plan=planner.plan(options), options=options,
                           windows=planner.WINDOWS, settles=planner.SETTLE_DAYS,
                           pairings=planner.PAIRINGS, better_by=planner.BETTER_BY,
                           min_days=planner.MIN_DAYS)


@rotation_bp.route("/swap", methods=["POST"])
@login_required
@requires_role("manager")
def swap():
    options = planner.Options.from_args(request.form)
    back = redirect(url_for("rotation.overview", **options.args()))
    try:
        out = db.session.get(Game, int(request.form.get("out", "")))
        into = db.session.get(Game, int(request.form.get("into", "")))
    except ValueError:
        out = into = None
    if out is None or into is None:
        flash("Pick a game on the floor and one in the warehouse.", "error")
        return back
    if out.location != "Floor" or into.location != "Warehouse" or "Retired" in (
            out.status, into.status):
        flash(f'Nothing moved: "{out.name}" has to be on the floor and "{into.name}" in the '
              "warehouse, and neither retired.", "error")
        return back
    planner.swap(out, into)
    db.session.commit()
    where = f" at {into.floor_position}" if into.floor_position else ""
    flash(f'Swapped: "{into.name}" is on the floor{where}, "{out.name}" is in the warehouse.',
          "success")
    return back
