"""Purchasing blueprint (inventory step 3): the shopping list, receiving deliveries, and
purchase orders for arcades that turn them on.

Managers decide what to buy (requests or purchase orders from the shopping list) and send,
cancel or close orders. Receiving a delivery is shelf work, so operators can do it. The work
is in ``app.services.purchasing``.
"""

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import (
    InventoryItem,
    InventoryRequest,
    PurchaseOrder,
    PurchaseOrderLine,
    StockPlace,
    Supplier,
)
from app.services import parts, purchasing, stock_places
from app.services.parts import PartError
from app.services.purchasing import PurchasingError
from app.utils.decorators import requires_role

purchasing_bp = Blueprint("purchasing", __name__, url_prefix="/inventory")


def _int(name, default=None):
    raw = (request.form.get(name) or "").strip()
    if not raw:
        return default
    if not raw.isdigit():
        raise PurchasingError(f"“{raw}” isn't a whole number.")
    return int(raw)


def _place():
    raw = request.form.get("place", "")
    if not raw:
        return None
    place = db.session.get(StockPlace, int(raw)) if raw.isdigit() else None
    if place is None or place.archived:
        raise PurchasingError("Pick a place from the list.")
    return place


def _price():
    try:
        return parts.clean_price(request.form.get("price"))
    except PartError as exc:
        raise PurchasingError(str(exc)) from None


def _places():
    return [(n.place, n.depth) for n in stock_places.place_tree()]


# --- the shopping list --------------------------------------------------------------------

@purchasing_bp.route("/shopping")
@login_required
@requires_role("manager")
def shopping():
    return render_template("shopping_list.html", groups=purchasing.shopping_list(),
                           orders_on=purchasing.orders_enabled(),
                           drafts=PurchaseOrder.query.filter_by(status="Draft").count())


def _picked():
    """(item, quantity) for every ticked row with a quantity above 0."""
    out = []
    for raw in request.form.getlist("item"):
        if not raw.isdigit():
            continue
        item = db.session.get(InventoryItem, int(raw))
        quantity = _int(f"qty-{raw}", 0)
        if item is not None and quantity > 0:
            out.append((item, quantity))
    return out


@purchasing_bp.route("/shopping/request", methods=["POST"])
@login_required
@requires_role("manager")
def shopping_request():
    """Turn the ticked rows into approved requests, one per part."""
    try:
        picked = _picked()
    except PurchasingError as exc:
        flash(str(exc), "error")
        return redirect(url_for("purchasing.shopping"))
    if not picked:
        flash("Tick at least one part, with how many to buy.", "error")
        return redirect(url_for("purchasing.shopping"))
    for item, quantity in picked:
        purchasing.request_from_list(item, quantity, current_user.id)
    db.session.commit()
    flash(f"Made {len(picked)} request{'' if len(picked) == 1 else 's'}, already approved.",
          "success")
    return redirect(url_for("inventory.inventory_requests_list"))


@purchasing_bp.route("/shopping/order", methods=["POST"])
@login_required
@requires_role("manager")
def shopping_order():
    """Put the ticked rows on draft purchase orders, one per preferred supplier."""
    if not purchasing.orders_enabled():
        abort(404)
    try:
        picked = _picked()
    except PurchasingError as exc:
        flash(str(exc), "error")
        return redirect(url_for("purchasing.shopping"))
    orders, skipped = {}, []
    for item, quantity in picked:
        link = parts.preferred(item)
        if link is None:
            skipped.append(item.name)
            continue
        order = orders.get(link.supplier_id) or purchasing.open_draft(link.supplier,
                                                                      current_user.id)
        orders[link.supplier_id] = order
        purchasing.add_line(order, item, quantity)
    db.session.commit()
    if skipped:
        flash(f"No supplier for {', '.join(skipped)}: give each a supplier, or request it "
              "instead.", "error")
    if orders:
        flash(f"Added to {len(orders)} draft order{'' if len(orders) == 1 else 's'}. Check "
              "them, then send.", "success")
        if len(orders) == 1:
            return redirect(url_for("purchasing.order", order_id=next(iter(orders.values())).id))
        return redirect(url_for("purchasing.orders"))
    return redirect(url_for("purchasing.shopping"))


@purchasing_bp.route("/shopping/settings", methods=["POST"])
@login_required
@requires_role("manager")
def shopping_settings():
    on = request.form.get("purchase_orders") == "on"
    purchasing.set_orders_enabled(on)
    db.session.commit()
    flash("Purchase orders are on." if on else "Purchase orders are off. Existing orders "
          "stay where they are.", "success")
    return redirect(url_for("purchasing.shopping"))


# --- receiving a request ------------------------------------------------------------------

@purchasing_bp.route("/requests/<int:request_id>/receive", methods=["POST"])
@login_required
@requires_role("operator")
def receive_request(request_id):
    from app.services.inventory import can_view_request

    req = db.get_or_404(InventoryRequest, request_id)
    if not can_view_request(current_user, req):
        # Who may receive it is who may see it: managers, and whoever asked for it
        # (security review, 2026-10-26).
        flash("You can only receive your own requests.", "error")
        return redirect(url_for("inventory.inventory_requests_list"))
    try:
        quantity = _int("quantity", purchasing.request_outstanding(req))
        message = purchasing.receive_request(req, quantity, _place(), current_user.id,
                                             _price(), request.form.get("update_price") == "1")
        db.session.commit()
        flash(message, "success")
    except (PurchasingError, stock_places.StockError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("inventory.inventory_request_detail", request_id=req.id))


# --- purchase orders ----------------------------------------------------------------------

def _order(order_id):
    return db.get_or_404(PurchaseOrder, order_id)


def _line(order_id, line_id):
    line = db.get_or_404(PurchaseOrderLine, line_id)
    if line.order_id != order_id:
        abort(404)
    return line


def _back(order):
    return redirect(url_for("purchasing.order", order_id=order.id))


@purchasing_bp.route("/orders")
@login_required
@requires_role("operator")
def orders():
    show = request.args.get("show", "open")
    query = PurchaseOrder.query
    if show != "all":
        query = query.filter(PurchaseOrder.status.in_(("Draft", "Sent", "Partly received")))
    rows = query.order_by(PurchaseOrder.id.desc()).all()
    suppliers = (Supplier.query.filter(Supplier.archived.is_(False))
                 .order_by(db.func.lower(Supplier.name)).all())
    return render_template("purchase_orders.html", orders=rows, show=show,
                           suppliers=suppliers, orders_on=purchasing.orders_enabled())


@purchasing_bp.route("/orders/new", methods=["POST"])
@login_required
@requires_role("manager")
def order_new():
    if not purchasing.orders_enabled():
        abort(404)
    raw = request.form.get("supplier", "")
    supplier = db.session.get(Supplier, int(raw)) if raw.isdigit() else None
    if supplier is None:
        flash("Pick a supplier.", "error")
        return redirect(url_for("purchasing.orders"))
    order = purchasing.draft_order(supplier, current_user.id)
    db.session.commit()
    return _back(order)


@purchasing_bp.route("/orders/<int:order_id>")
@login_required
@requires_role("operator")
def order(order_id):
    order = _order(order_id)
    names = [n for (n,) in db.session.query(InventoryItem.name).order_by(InventoryItem.name)]
    return render_template("purchase_order.html", order=order, places=_places(),
                           names=names, default_place=purchasing.default_place)


@purchasing_bp.route("/orders/<int:order_id>/edit", methods=["POST"])
@login_required
@requires_role("manager")
def order_edit(order_id):
    import datetime as dt

    order = _order(order_id)
    order.notes = (request.form.get("notes") or "").strip()[:2000] or None
    raw = (request.form.get("expected") or "").strip()
    try:
        order.expected = dt.date.fromisoformat(raw) if raw else None
    except ValueError:
        flash("The expected date must look like 2026-11-02.", "error")
        return _back(order)
    db.session.commit()
    flash("Saved.", "success")
    return _back(order)


@purchasing_bp.route("/orders/<int:order_id>/lines/new", methods=["POST"])
@login_required
@requires_role("manager")
def line_new(order_id):
    order = _order(order_id)
    item = stock_places.find_part(request.form.get("part"))
    try:
        if item is None:
            raise PurchasingError("No part by that name, number or label. Add it to the "
                                  "parts list first.")
        purchasing.add_line(order, item, _int("quantity", 0), _price())
        db.session.commit()
    except PurchasingError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return _back(order)


@purchasing_bp.route("/orders/<int:order_id>/lines/<int:line_id>/edit", methods=["POST"])
@login_required
@requires_role("manager")
def line_edit(order_id, line_id):
    line = _line(order_id, line_id)
    try:
        purchasing.edit_line(line, _int("quantity", 0), _price())
        db.session.commit()
    except PurchasingError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return _back(line.order)


@purchasing_bp.route("/orders/<int:order_id>/lines/<int:line_id>/remove", methods=["POST"])
@login_required
@requires_role("manager")
def line_remove(order_id, line_id):
    line = _line(order_id, line_id)
    order = line.order
    try:
        purchasing.remove_line(line)
        db.session.commit()
    except PurchasingError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return _back(order)


@purchasing_bp.route("/orders/<int:order_id>/<any(send, cancel, close):action>",
                     methods=["POST"])
@login_required
@requires_role("manager")
def order_action(order_id, action):
    order = _order(order_id)
    try:
        getattr(purchasing, action)(order)
        db.session.commit()
    except PurchasingError as exc:
        db.session.rollback()
        flash(str(exc), "error")
    else:
        flash({"send": f"Order #{order.id} marked sent.",
               "cancel": f"Order #{order.id} cancelled.",
               "close": f"Order #{order.id} closed."}[action], "success")
    return _back(order)


@purchasing_bp.route("/orders/<int:order_id>/lines/<int:line_id>/receive", methods=["POST"])
@login_required
@requires_role("operator")
def line_receive(order_id, line_id):
    line = _line(order_id, line_id)
    try:
        quantity = _int("quantity", line.outstanding)
        message = purchasing.receive_line(line, quantity, _place(), current_user.id, _price(),
                                          request.form.get("update_price") == "1")
        db.session.commit()
        flash(f"Received {message}", "success")
    except (PurchasingError, stock_places.StockError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return _back(line.order)
