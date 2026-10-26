"""Places blueprint: where parts are kept (inventory step 1).

A free tree: rooms, shelves, drawers, bins, carts and vans, nested as the building needs.
Operators make and rename places as they go, which is how the first count is done; managers
archive and delete them. Stock itself changes on the part's page (and, next, in count mode),
through ``app.services.stock_places``.
"""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import InventoryItem, StockLevel, StockPlace
from app.models.stock import MAX_DEPTH
from app.services import stock_places
from app.services.stock_places import StockError
from app.utils.decorators import requires_role

places_bp = Blueprint("places", __name__, url_prefix="/inventory/places")
MAX_NOTES = 2000


def _parent_from_form():
    raw = request.form.get("parent", "")
    if not raw:
        return None
    parent = db.session.get(StockPlace, int(raw)) if raw.isdigit() else None
    if parent is None or parent.archived:
        raise StockError("Pick a place from the list to put it in.")
    return parent


def _notes_from_form():
    notes = (request.form.get("notes") or "").strip()
    if len(notes) > MAX_NOTES:
        raise StockError(f"Keep the notes to {MAX_NOTES} characters.")
    return notes or None


def _parents_for(place=None):
    """Places a place may go inside: not itself or its contents, not Unsorted, not too deep."""
    out = []
    for node in stock_places.place_tree():
        try:
            stock_places.check_parent(place, node.place)
        except StockError:
            continue
        out.append(node)
    return out


@places_bp.route("/")
@login_required
@requires_role("operator")
def overview():
    show_archived = request.args.get("archived") == "1"
    return render_template("places.html", tree=stock_places.place_tree(show_archived),
                           parents=_parents_for(), show_archived=show_archived,
                           archived_count=StockPlace.query.filter_by(archived=True).count(),
                           max_depth=MAX_DEPTH)


@places_bp.route("/new", methods=["POST"])
@login_required
@requires_role("operator")
def create():
    back = request.form.get("back") in ("place", "count")
    try:
        name = stock_places.clean_name(request.form.get("name"))
        parent = _parent_from_form()
        stock_places.check_parent(None, parent)
        if stock_places.sibling_taken(name, parent):
            raise StockError(f"There is already a {name} there.")
        place = StockPlace(name=name, parent=parent, notes=_notes_from_form())
        db.session.add(place)
        db.session.commit()
    except StockError as exc:
        db.session.rollback()
        flash(str(exc), "error")
        parent_id = request.form.get("parent", "")
        if back and parent_id.isdigit():
            target = "places.count" if request.form.get("back") == "count" else "places.detail"
            return redirect(url_for(target, place_id=int(parent_id)))
        return redirect(url_for("places.overview"))
    flash(f"Added {place.path}.", "success")
    if request.form.get("back") == "count":
        return redirect(url_for("places.count", place_id=place.id))
    if back and parent is not None:
        return redirect(url_for("places.detail", place_id=parent.id))
    return redirect(url_for("places.detail", place_id=place.id))


@places_bp.route("/<int:place_id>")
@login_required
@requires_role("operator")
def detail(place_id):
    place = db.get_or_404(StockPlace, place_id)
    nodes = {n.place.id: n for n in stock_places.place_tree(include_archived=True)}
    children = sorted(place.children, key=lambda p: (p.archived, p.name.lower()))
    here = (StockLevel.query.filter_by(place_id=place.id)
            .filter(StockLevel.quantity > 0).all())
    here.sort(key=lambda lv: lv.item.name.lower())
    return render_template("place_detail.html", place=place, children=children, nodes=nodes,
                           here=here, parents=_parents_for(place),
                           can_nest=len(place.lineage()) < MAX_DEPTH and not place.is_unsorted,
                           holds_stock=stock_places.place_holds_stock(place))


@places_bp.route("/<int:place_id>/edit", methods=["POST"])
@login_required
@requires_role("operator")
def edit(place_id):
    place = db.get_or_404(StockPlace, place_id)
    try:
        if place.is_unsorted:
            raise StockError("Unsorted keeps its name and place.")
        name = stock_places.clean_name(request.form.get("name"))
        parent = _parent_from_form()
        stock_places.check_parent(place, parent)
        if stock_places.sibling_taken(name, parent, place):
            raise StockError(f"There is already a {name} there.")
        place.name, place.parent, place.notes = name, parent, _notes_from_form()
        db.session.commit()
    except StockError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    else:
        flash(f"Saved {place.path}.", "success")
    return redirect(url_for("places.detail", place_id=place.id))


@places_bp.route("/<int:place_id>/archive", methods=["POST"])
@login_required
@requires_role("manager")
def archive(place_id):
    """Archive (or restore) a place. Only an empty one, and its contents go with it."""
    place = db.get_or_404(StockPlace, place_id)
    if place.is_unsorted:
        flash("Unsorted can't be archived.", "error")
    elif place.archived:
        if place.parent is not None and place.parent.archived:
            flash(f"Restore {place.parent.path} first.", "error")
        else:
            place.archived = False
            db.session.commit()
            flash(f"Restored {place.path}.", "success")
    elif stock_places.place_holds_stock(place):
        flash("Move or count out what's in it first: it still holds parts.", "error")
    else:
        for p in [place, *place.descendants()]:
            p.archived = True
        db.session.commit()
        flash(f"Archived {place.path}.", "success")
    return redirect(url_for("places.detail", place_id=place.id))


@places_bp.route("/<int:place_id>/delete", methods=["POST"])
@login_required
@requires_role("manager")
def delete(place_id):
    """Delete a place nothing refers to: no parts (even counted at zero), no places inside.
    History rows that named it keep their change and lose the place."""
    place = db.get_or_404(StockPlace, place_id)
    if place.is_unsorted:
        flash("Unsorted can't be deleted.", "error")
        return redirect(url_for("places.detail", place_id=place.id))
    if place.children or place.levels or place.count_lines:
        # A count that listed it keeps pointing at it (security review, 2026-10-26).
        flash("Only an empty place with nothing inside it, on no count, can be deleted. "
              "Archive it instead.", "error")
        return redirect(url_for("places.detail", place_id=place.id))
    path, parent = place.path, place.parent
    db.session.delete(place)
    db.session.commit()
    flash(f"Deleted {path}.", "success")
    if parent is not None:
        return redirect(url_for("places.detail", place_id=parent.id))
    return redirect(url_for("places.overview"))


# --- count mode (the first inventory, and every count after it) ----------------------------

def _counting(place):
    """The rows count mode offers: every part with a level here, even one counted at zero."""
    rows = StockLevel.query.filter_by(place_id=place.id).all()
    rows.sort(key=lambda lv: lv.item.name.lower())
    return rows


def _count_page(place, status=200, **extra):
    from app.models.stock import MAX_DEPTH as depth

    names = [n for (n,) in db.session.query(InventoryItem.name)
             .order_by(InventoryItem.name).all()]
    return render_template("place_count.html", place=place, rows=_counting(place),
                           names=names, children=sorted(
                               (c for c in place.children if not c.archived),
                               key=lambda c: c.name.lower()),
                           can_nest=len(place.lineage()) < depth and not place.is_unsorted,
                           **extra), status


@places_bp.route("/<int:place_id>/count")
@login_required
@requires_role("operator")
def count(place_id):
    """Stand in a place with a phone: each part here, a box for how many, and a way to add
    the ones that aren't listed yet (scan, type, or make a new part)."""
    place = db.get_or_404(StockPlace, place_id)
    if place.archived:
        flash("Restore this place before counting it.", "error")
        return redirect(url_for("places.detail", place_id=place.id))
    return _count_page(place)


@places_bp.route("/<int:place_id>/count", methods=["POST"])
@login_required
@requires_role("operator")
def save_counts(place_id):
    """Every box with a number is that part's count here; blank boxes are left alone."""
    place = db.get_or_404(StockPlace, place_id)
    counted, changed = 0, 0
    try:
        if place.archived:
            raise StockError("Restore this place before counting it.")
        for level in _counting(place):
            value = stock_places.parse_count(request.form.get(f"count-{level.item_id}"))
            if value is None:
                continue
            counted += 1
            if stock_places.count(level.item, value, current_user.id, place):
                changed += 1
        db.session.commit()
    except StockError as exc:
        db.session.rollback()
        flash(f"Nothing was saved: {exc}", "error")
        return redirect(url_for("places.count", place_id=place.id))
    if counted:
        flash(f"Counted {counted} part{'' if counted == 1 else 's'} in {place.path}"
              f"{f'; {changed} changed' if changed else ', no changes'}.", "success")
    else:
        flash("Nothing to save: type a number in the box of each part you counted.", "info")
    return redirect(url_for("places.count", place_id=place.id))


@places_bp.route("/<int:place_id>/count/add", methods=["POST"])
@login_required
@requires_role("operator")
def count_add(place_id):
    """Count one part that isn't on this place's list yet. An unknown name is only made into
    a new part once the person confirms it, so a typo doesn't become a part."""
    place = db.get_or_404(StockPlace, place_id)
    part = (request.form.get("part") or "").strip()
    raw_qty = request.form.get("quantity")
    try:
        if place.archived:
            raise StockError("Restore this place before counting it.")
        quantity = stock_places.parse_count(raw_qty)
        if quantity is None:
            raise StockError("Type how many there are (0 is fine).")
        item = stock_places.find_part(part)
        if item is None:
            if not part:
                raise StockError("Scan the part's label, or type its name.")
            if request.form.get("create") != "1":
                return _count_page(place, 200, confirm={"part": part, "quantity": quantity})
            item = stock_places.new_part(part)
            made = True
        else:
            made = False
        stock_places.count(item, quantity, current_user.id, place,
                           "First counted here" if made else "")
        db.session.commit()
    except StockError as exc:
        db.session.rollback()
        return _count_page(place, 400, add_error=str(exc), part=part, quantity=raw_qty)
    flash(f"{'New part: ' if made else ''}{item.name}, {quantity} in {place.name}.", "success")
    return redirect(url_for("places.count", place_id=place.id))
