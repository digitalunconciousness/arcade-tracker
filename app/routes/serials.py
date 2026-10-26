"""Serial units blueprint (inventory step 4): parts tracked one by one.

Operators record units and move them: shelf to shelf, into and out of machines, out for
repair and back, and retire them. Managers correct a unit's serial. A unit's label encodes
/u/<code>, which never changes. The work is in ``app.services.serials``.
"""

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Game, InventoryItem, SerialUnit, StockPlace
from app.services import serials, stock_places
from app.services.serials import SerialError
from app.utils.decorators import requires_role

serials_bp = Blueprint("serials", __name__)


def _place(field="place"):
    raw = request.form.get(field, "")
    place = db.session.get(StockPlace, int(raw)) if raw.isdigit() else None
    if place is None:
        raise SerialError("Pick a place from the list.")
    return place


def _note():
    return (request.form.get("note") or "").strip()


@serials_bp.route("/u/<code>")
@login_required
def resolve(code):
    """A unit's label: opens the unit."""
    unit = SerialUnit.query.filter_by(code=code.lower()).first()
    if unit is None:
        flash(f"No unit found for scanned code '{code}'.", "error")
        return redirect(url_for("games.scan"))
    return redirect(url_for("serials.unit", unit_id=unit.id))


@serials_bp.route("/inventory/<int:item_id>/units/new", methods=["POST"])
@login_required
@requires_role("operator")
def add(item_id):
    item = db.get_or_404(InventoryItem, item_id)
    try:
        units = serials.add_units(item, request.form.get("serials"), _place(),
                                  current_user.id, request.form.get("arriving") == "1",
                                  _note())
        db.session.commit()
        flash(f"Added {len(units)} unit{'' if len(units) == 1 else 's'}.", "success")
    except (SerialError, stock_places.StockError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("inventory.inventory_detail", item_id=item.id) + "#units-title")


@serials_bp.route("/inventory/units/<int:unit_id>")
@login_required
@requires_role("operator")
def unit(unit_id):
    unit = db.get_or_404(SerialUnit, unit_id)
    machines = Game.query.order_by(Game.name).all()
    places = [(n.place, n.depth) for n in stock_places.place_tree()]
    from app.services.purchasing import default_place

    return render_template("serial_unit.html", unit=unit, machines=machines, places=places,
                           default_place=default_place(unit.item))


@serials_bp.route("/inventory/units/<int:unit_id>/"
                  "<any(move, install, remove, repair, back, retire):action>",
                  methods=["POST"])
@login_required
@requires_role("operator")
def act(unit_id, action):
    unit = db.get_or_404(SerialUnit, unit_id)
    try:
        if action == "move":
            serials.move(unit, _place(), current_user.id, _note())
        elif action == "install":
            raw = request.form.get("game", "")
            game = db.session.get(Game, int(raw)) if raw.isdigit() else None
            serials.install(unit, game, current_user.id, _note())
        elif action == "remove":
            serials.remove(unit, _place(), current_user.id, _note())
        elif action == "repair":
            serials.send_for_repair(unit, request.form.get("repair_with"), current_user.id,
                                    _note())
        elif action == "back":
            serials.back_from_repair(unit, _place(), current_user.id, _note())
        elif action == "retire":
            serials.retire(unit, current_user.id, _note())
        else:                                                      # pragma: no cover
            abort(404)
        db.session.commit()
        flash(f"{unit.item.name} {unit.serial}: {unit.where}.", "success")
    except (SerialError, stock_places.StockError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("serials.unit", unit_id=unit.id))


@serials_bp.route("/inventory/units/<int:unit_id>/edit", methods=["POST"])
@login_required
@requires_role("manager")
def edit(unit_id):
    """Correct a mistyped serial, or the notes. The label code stays."""
    unit = db.get_or_404(SerialUnit, unit_id)
    serial = " ".join((request.form.get("serial") or "").split())
    if not serial or len(serial) > serials.MAX_SERIAL:
        flash(f"A serial number is 1 to {serials.MAX_SERIAL} characters.", "error")
        return redirect(url_for("serials.unit", unit_id=unit.id))
    other = serials.find_unit(unit.item, serial)
    if other is not None and other is not unit:
        flash(f"{unit.item.name} already has a unit {other.serial}.", "error")
        return redirect(url_for("serials.unit", unit_id=unit.id))
    if serial != unit.serial:
        serials._event(unit, "edited", f"Serial {unit.serial} → {serial}", current_user.id)
    unit.serial = serial
    unit.notes = (request.form.get("notes") or "").strip()[:2000] or None
    db.session.commit()
    flash("Saved.", "success")
    return redirect(url_for("serials.unit", unit_id=unit.id))
