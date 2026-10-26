"""Counts blueprint (inventory step 5): planned full and cycle counts.

Managers start counts and review and apply them; operators do the counting, blind (the
counting page never shows what's on record). The work is in ``app.services.counts``.
"""

import datetime as dt

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import StockCount, StockCountLine, StockPlace
from app.services import counts, stock_places
from app.services.counts import CountError
from app.utils.decorators import requires_role

counts_bp = Blueprint("counts", __name__, url_prefix="/inventory/counts")


def _count(count_id):
    return db.get_or_404(StockCount, count_id)


def _int(raw, what):
    raw = (raw or "").strip()
    if not raw:
        return None
    if not raw.isdigit():
        raise CountError(f"“{raw}” isn't a whole number ({what}).")
    return int(raw)


@counts_bp.route("/")
@login_required
@requires_role("operator")
def overview():
    open_counts = (StockCount.query.filter_by(status="Counting")
                   .order_by(StockCount.due.is_(None), StockCount.due, StockCount.id).all())
    done = (StockCount.query.filter(StockCount.status != "Counting")
            .order_by(StockCount.id.desc()).limit(20).all())
    return render_template("stock_counts.html", open_counts=open_counts, done=done,
                           tree=stock_places.place_tree(), overdue=counts.overdue(),
                           today=counts.local_today())


@counts_bp.route("/new", methods=["POST"])
@login_required
@requires_role("manager")
def new():
    kind = request.form.get("kind", "full")
    try:
        due_raw = (request.form.get("due") or "").strip()
        try:
            due = dt.date.fromisoformat(due_raw) if due_raw else None
        except ValueError:
            raise CountError("The due date must look like 2026-11-02.") from None
        repeat = _int(request.form.get("repeat_days"), "repeat")
        if kind == "cycle":
            count = counts.start_cycle(request.form.get("name"),
                                       _int(request.form.get("size"), "parts") or 0,
                                       current_user.id, due, repeat)
        else:
            ids = [int(i) for i in request.form.getlist("place") if i.isdigit()]
            places = StockPlace.query.filter(StockPlace.id.in_(ids or [0])).all()
            count = counts.start_full(request.form.get("name"), places, current_user.id,
                                      due, repeat)
        db.session.commit()
    except CountError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("counts.overview"))
    flash(f"Started {count.name}: {len(count.lines)} to count.", "success")
    return redirect(url_for("counts.sheet", count_id=count.id))


@counts_bp.route("/<int:count_id>")
@login_required
@requires_role("operator")
def sheet(count_id):
    """The counting page: blind, grouped by place."""
    count = _count(count_id)
    by_place: dict[int, list[StockCountLine]] = {}
    for line in count.lines:
        by_place.setdefault(line.place_id, []).append(line)
    groups = sorted(((lines[0].place, sorted(lines, key=lambda ln: ln.item.name.lower()))
                     for lines in by_place.values()), key=lambda g: g[0].path)
    from app.models import InventoryItem

    names = [n for (n,) in db.session.query(InventoryItem.name).order_by(InventoryItem.name)]
    places = [(n.place, n.depth) for n in stock_places.place_tree()]
    return render_template("stock_count.html", count=count, groups=groups, names=names,
                           places=places)


@counts_bp.route("/<int:count_id>/save", methods=["POST"])
@login_required
@requires_role("operator")
def save(count_id):
    """Every box with a number is recorded; a box that was emptied is cleared; untouched
    boxes are left alone."""
    count = _count(count_id)
    saved = 0
    try:
        for line in count.lines:
            key = f"line-{line.id}"
            if key not in request.form:
                continue
            value = stock_places.parse_count(request.form.get(key))
            if value != line.counted:
                counts.record(line, value, current_user.id)
                saved += 1
        db.session.commit()
    except (CountError, stock_places.StockError) as exc:
        db.session.rollback()
        flash(f"Nothing was saved: {exc}", "error")
        return redirect(url_for("counts.sheet", count_id=count.id))
    flash(f"Saved {saved} count{'' if saved == 1 else 's'}. {count.counted} of "
          f"{len(count.lines)} counted.", "success")
    return redirect(url_for("counts.sheet", count_id=count.id))


@counts_bp.route("/<int:count_id>/found", methods=["POST"])
@login_required
@requires_role("operator")
def found(count_id):
    """A part found somewhere the count didn't list it."""
    count = _count(count_id)
    try:
        item = stock_places.find_part(request.form.get("part"))
        if item is None:
            raise CountError("No part by that name, number or label. Add new parts from "
                             "the parts list or quick count mode.")
        raw = request.form.get("place", "")
        place = db.session.get(StockPlace, int(raw)) if raw.isdigit() else None
        if place is None:
            raise CountError("Pick the place it was found in.")
        value = stock_places.parse_count(request.form.get("quantity"))
        if value is None:
            raise CountError("Type how many there are.")
        counts.add_found(count, item, place, value, current_user.id)
        db.session.commit()
        flash(f"{item.name}: {value} in {place.path}.", "success")
    except (CountError, stock_places.StockError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("counts.sheet", count_id=count.id))


@counts_bp.route("/<int:count_id>/review")
@login_required
@requires_role("manager")
def review(count_id):
    count = _count(count_id)
    differ, match, missing = counts.review(count)
    return render_template("stock_count_review.html", count=count, differ=differ,
                           match=match, missing=missing)


@counts_bp.route("/<int:count_id>/<any(apply, cancel):action>", methods=["POST"])
@login_required
@requires_role("manager")
def finish(count_id, action):
    count = _count(count_id)
    try:
        if action == "apply":
            changed, nxt = counts.apply(count, current_user.id)
            db.session.commit()
            flash(f"Applied {count.name}: {changed} place{'' if changed == 1 else 's'} "
                  f"changed." + (f" The next one is due {nxt.due:%Y-%m-%d}." if nxt else ""),
                  "success")
        elif action == "cancel":
            counts.cancel(count)
            db.session.commit()
            flash(f"Cancelled {count.name}. Nothing was changed.", "success")
        else:                                                        # pragma: no cover
            abort(404)
    except CountError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        return redirect(url_for("counts.review", count_id=count.id))
    return redirect(url_for("counts.overview"))
