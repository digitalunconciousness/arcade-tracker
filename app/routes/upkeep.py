"""Preventive maintenance tasks (feature step 5). See app/services/upkeep.py."""
from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Game, MaintenanceRecord, MaintenanceTask
from app.models.upkeep import APPLIES_TO
from app.services import upkeep
from app.utils.decorators import requires_role

upkeep_bp = Blueprint("upkeep", __name__, url_prefix="/maintenance/tasks")

MAX_PLAYS = 10_000_000
MAX_DAYS = 3650


@upkeep_bp.route("/")
@login_required
def overview():
    raised = upkeep.raise_due()
    if raised:
        flash(f"{len(raised)} preventive maintenance order{'s' if len(raised) > 1 else ''} "
              "raised.", "info")
    tasks = MaintenanceTask.query.order_by(MaintenanceTask.active.desc(),
                                           MaintenanceTask.name).all()
    by_task: dict[int, list] = {}
    for s in upkeep.standings([t for t in tasks if t.active]):
        by_task.setdefault(s.task.id, []).append(s)
    for rows in by_task.values():
        rows.sort(key=lambda s: (s.state == "ok", -s.share, s.game.name.lower()))
    return render_template("upkeep.html", tasks=tasks, by_task=by_task)


def _parse(form) -> tuple[dict, dict[str, str]]:
    errors: dict[str, str] = {}
    v = {"name": (form.get("name") or "").strip(),
         "instructions": (form.get("instructions") or "").strip() or None,
         "applies_to": form.get("applies_to") or "all",
         "active": form.get("active") == "1"}
    if not v["name"]:
        errors["name"] = "Name the task, like \"Clean the coin mech\"."
    elif len(v["name"]) > 100:
        errors["name"] = "Keep the name to 100 characters."
    for key, top, what in (("every_plays", MAX_PLAYS, "plays"), ("every_days", MAX_DAYS, "days")):
        raw = (form.get(key) or "").strip().replace(",", "")
        if not raw:
            v[key] = None
            continue
        try:
            v[key] = int(raw)
        except ValueError:
            v[key] = None
            errors[key] = f"The {what} must be a whole number."
            continue
        if not 1 <= v[key] <= top:
            errors[key] = f"Between 1 and {top:,} {what}."
    if not errors.get("every_plays") and not errors.get("every_days") \
            and v["every_plays"] is None and v["every_days"] is None:
        errors["every_plays"] = "Give a number of plays, a number of days, or both."
    if v["applies_to"] not in APPLIES_TO:
        errors["applies_to"] = "Pick what it applies to."
    v["game_id"] = None
    if v["applies_to"] == "machine":
        try:
            game = db.session.get(Game, int(form.get("game_id") or 0))
        except ValueError:
            game = None
        if game is None:
            errors["game_id"] = "Pick the machine."
        else:
            v["game_id"] = game.id
    return v, errors


def _form(task: MaintenanceTask | None):
    games = Game.query.filter(Game.status != "Retired").order_by(Game.name).all()
    if request.method == "GET":
        values = ({"name": task.name, "instructions": task.instructions or "",
                   "every_plays": task.every_plays or "", "every_days": task.every_days or "",
                   "applies_to": task.applies_to, "game_id": task.game_id,
                   "active": task.active} if task else
                  {"applies_to": "all", "active": True})
        return render_template("upkeep_form.html", task=task, values=values, errors={},
                               games=games, applies=APPLIES_TO)
    v, errors = _parse(request.form)
    if errors:
        return render_template("upkeep_form.html", task=task, values=v, errors=errors,
                               games=games, applies=APPLIES_TO), 400
    if task is None:
        task = MaintenanceTask(created_by_id=current_user.id)
        db.session.add(task)
    for key, value in v.items():
        setattr(task, key, value)
    db.session.commit()
    flash(f'Saved "{task.name}": {task.rule.lower()}, {task.scope.lower()}.', "success")
    return redirect(url_for("upkeep.overview"))


@upkeep_bp.route("/new", methods=["GET", "POST"])
@login_required
@requires_role("manager")
def new():
    return _form(None)


@upkeep_bp.route("/<int:task_id>/edit", methods=["GET", "POST"])
@login_required
@requires_role("manager")
def edit(task_id):
    return _form(db.get_or_404(MaintenanceTask, task_id))


@upkeep_bp.route("/<int:task_id>/delete", methods=["POST"])
@login_required
@requires_role("manager")
def delete(task_id):
    task = db.get_or_404(MaintenanceTask, task_id)
    name = task.name
    # By hand, not by the foreign key: SQLite here doesn't enforce ON DELETE SET NULL.
    MaintenanceRecord.query.filter_by(pm_task_id=task.id).update(
        {MaintenanceRecord.pm_task_id: None}, synchronize_session=False)
    db.session.delete(task)
    db.session.commit()
    flash(f'Deleted "{name}". Orders it raised stay, as ordinary work orders.', "success")
    return redirect(url_for("upkeep.overview"))
