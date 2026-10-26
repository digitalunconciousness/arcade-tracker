"""Labels for places and parts (inventory step 1), and the addresses they encode.

**Printed labels encode /p/<code> (a place), /i/<code> (a part) and /u/<code> (a unit of a
part tracked one by one, step 4): these never change**,
like the machines' /g/<barcode>. The codes are made once (``app.models.stock.new_code``) and
never edited. The sheet reuses the machine labels' formats and template.
"""

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import login_required

from app.extensions import db
from app.models import InventoryItem, SerialUnit, StockPlace
from app.services import stock_places
from app.services.labels import FORMATS, address_problem, label_format, pages
from app.utils.decorators import requires_role

stock_labels_bp = Blueprint("stock_labels", __name__)


@stock_labels_bp.route("/p/<code>")
@login_required
def resolve_place(code):
    """A place's label. Opens the place, where count mode is one tap away."""
    place = StockPlace.query.filter_by(code=code.lower()).first()
    if place is None:
        flash(f"No place found for scanned code '{code}'.", "error")
        return redirect(url_for("games.scan"))
    return redirect(url_for("places.detail", place_id=place.id))


@stock_labels_bp.route("/i/<code>")
@login_required
def resolve_part(code):
    """A part's label. Opens the part: where it is, and take, add, count or move."""
    item = InventoryItem.query.filter_by(code=code.lower()).first()
    if item is None:
        flash(f"No part found for scanned code '{code}'.", "error")
        return redirect(url_for("games.scan"))
    return redirect(url_for("inventory.inventory_detail", item_id=item.id))


def _base_url() -> str:
    return (current_app.config.get("BASE_URL") or request.host_url).rstrip("/")


def _qr(url: str) -> str:
    import segno

    # The same scale as the machine labels: the printed size comes from labels.css.
    return segno.make(url, error="m").svg_data_uri(scale=4, border=2)


def _picked():
    """The places, parts and units in ``ids`` ("p3,i12,u7", or repeated ``ids``), in that
    order. None for a malformed link."""
    tokens = [t for raw in request.args.getlist("ids") for t in raw.split(",") if t.strip()]
    found = {"p": [], "i": [], "u": []}
    models = {"p": StockPlace, "i": InventoryItem, "u": SerialUnit}
    for token in (t.strip().lower() for t in tokens):
        kind, number = token[:1], token[1:]
        if kind not in models or not number.isdigit():
            return None
        row = db.session.get(models[kind], int(number))
        if row is not None and row not in found[kind]:
            found[kind].append(row)
    return found["p"], found["i"], found["u"]


def place_label(place) -> dict:
    url = f"{_base_url()}/p/{place.code}"
    above = place.parent.path if place.parent else None
    return {"name": place.name, "lines": [x for x in (above, place.code) if x],
            "url": url, "qr": _qr(url)}


def unit_label(unit) -> dict:
    """A unit of a part tracked one by one (step 4): /u/<code>."""
    url = f"{_base_url()}/u/{unit.code}"
    return {"name": unit.item.name, "lines": [f"S/N {unit.serial}", unit.code],
            "url": url, "qr": _qr(url)}


def part_label(item) -> dict:
    url = f"{_base_url()}/i/{item.code}"
    return {"name": item.name, "lines": [x for x in (item.part_number, item.code) if x],
            "url": url, "qr": _qr(url)}


@stock_labels_bp.route("/inventory/labels")
@login_required
@requires_role("operator")
def pick():
    """Choose places and parts for a label sheet."""
    items = InventoryItem.query.order_by(InventoryItem.name).all()
    return render_template("stock_label_pick.html", tree=stock_places.place_tree(),
                           items=items, formats=FORMATS.values())


@stock_labels_bp.route("/inventory/labels/sheet")
@login_required
@requires_role("operator")
def sheet():
    picked = _picked()
    if picked is None:
        flash("That label sheet link is malformed; pick the places and parts again.", "error")
        return redirect(url_for("stock_labels.pick"))
    places, items, units = picked
    labels = ([place_label(p) for p in places] +
              [part_label(i) for i in items if i.code] +
              [unit_label(u) for u in units])
    if not labels:
        flash("Nothing selected to print.", "error")
        return redirect(url_for("stock_labels.pick"))
    fmt = label_format(request.args.get("format"))
    example = labels[0]["url"]
    return render_template(
        "stock_label_sheet.html", labels=labels, kind="stock", fmt=fmt,
        formats=FORMATS.values(), pages=pages(labels, fmt), example_url=example,
        address_problem=address_problem(example),
        base_url_set=bool(current_app.config.get("BASE_URL")),
        ids=",".join([f"p{p.id}" for p in places] + [f"i{i.id}" for i in items]
                     + [f"u{u.id}" for u in units]),
        n_places=len(places), n_items=len(labels) - len(places) - len(units),
        n_units=len(units))
