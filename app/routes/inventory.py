"""Inventory blueprint: parts, stock, low-stock alerts, part requests and shipments.

The work is in app/services/inventory.py; these views parse the request and report.
"""

import datetime as dt
import os
from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.forms.inventory import InventoryItemForm, StockAdjustmentForm
from app.models import (
    Game,
    InventoryItem,
    InventoryRequest,
    LowStockAlert,
    MaintenanceRecord,
)
from app.security.utils import log_security_event
from app.services import inventory as inv
from app.services.work_orders import OPEN_STATUSES
from app.utils.decorators import requires_role

inventory_bp = Blueprint("inventory", __name__, url_prefix="/inventory")


def _machine_choices(form):
    form.compatible_games.choices = [
        (g.id, g.name) for g in Game.query.order_by(Game.name.asc()).all()]


# --- items ---------------------------------------------------------------------------------

@inventory_bp.route("/")
@login_required
@requires_role("operator")
def inventory_list():
    search = request.args.get("search", "").strip()
    low_only = bool(request.args.get("low_stock"))
    return render_template("inventory_list.html",
                           data=inv.list_items(current_user, search, low_only),
                           search=search, low_only=low_only)


@inventory_bp.route("/add", methods=["GET", "POST"])
@login_required
@requires_role("manager")
def add_inventory_item():
    form = InventoryItemForm()
    _machine_choices(form)
    if form.validate_on_submit():
        item = InventoryItem()
        inv.save_item(item, form, current_user.id)
        db.session.commit()
        flash(f'Added "{item.name}".', "success")
        return redirect(url_for("inventory.inventory_list"))
    status = 400 if request.method == "POST" else 200
    return render_template("inventory_form.html", form=form, item=None), status


@inventory_bp.route("/<int:item_id>")
@login_required
@requires_role("operator")
def inventory_detail(item_id):
    item = db.get_or_404(InventoryItem, item_id)
    active_alert = LowStockAlert.query.filter_by(item_id=item.id, resolved=False).first()
    return render_template("inventory_detail.html", item=item,
                           history=inv.item_history(item), active_alert=active_alert,
                           adjust_form=StockAdjustmentForm(), adjustments=inv.ADJUSTMENTS,
                           requests=sorted(item.requests, key=lambda r: r.id, reverse=True)[:5])


@inventory_bp.route("/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
@requires_role("manager")
def edit_inventory_item(item_id):
    item = db.get_or_404(InventoryItem, item_id)
    form = InventoryItemForm(obj=item)
    _machine_choices(form)
    if request.method == "GET":
        form.compatible_games.data = [g.id for g in item.compatible_games]
    if form.validate_on_submit():
        inv.save_item(item, form, current_user.id)
        db.session.commit()
        flash(f'Saved "{item.name}".', "success")
        return redirect(url_for("inventory.inventory_detail", item_id=item.id))
    status = 400 if request.method == "POST" else 200
    return render_template("inventory_form.html", form=form, item=item), status


@inventory_bp.route("/<int:item_id>/adjust_stock", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def adjust_stock(item_id):
    item = db.get_or_404(InventoryItem, item_id)
    form = StockAdjustmentForm()
    if form.validate_on_submit():
        before, after = inv.adjust_stock(item, form.adjustment_type.data, form.quantity.data,
                                         form.reason.data, current_user.id)
        db.session.commit()
        flash(f'Stock for "{item.name}": {before} → {after}.', "success")
        return redirect(url_for("inventory.inventory_detail", item_id=item.id))
    status = 400 if request.method == "POST" else 200
    return render_template("adjust_stock.html", form=form, item=item), status


@inventory_bp.route("/<int:item_id>/delete", methods=["POST"])
@login_required
@requires_role("admin")
def delete_inventory_item(item_id):
    item = db.get_or_404(InventoryItem, item_id)
    name = item.name
    refusal = inv.delete_item(item)
    if refusal:
        flash(refusal, "error")
        return redirect(url_for("inventory.inventory_detail", item_id=item_id))
    db.session.commit()
    flash(f'Deleted "{name}".', "success")
    return redirect(url_for("inventory.inventory_list"))


@inventory_bp.route("/low_stock_alerts")
@login_required
@requires_role("manager")
def low_stock_alerts():
    active, resolved = inv.alerts()
    return render_template("low_stock_alerts.html", active_alerts=active,
                           recent_resolved=resolved)


@inventory_bp.route("/resolve_alert/<int:alert_id>", methods=["POST"])
@login_required
@requires_role("manager")
def resolve_low_stock_alert(alert_id):
    alert = db.get_or_404(LowStockAlert, alert_id)
    alert.resolved = True
    alert.resolved_date = datetime.now(dt.UTC)
    db.session.commit()
    flash(f'Alert for "{alert.item.name}" resolved.', "success")
    return redirect(url_for("inventory.low_stock_alerts"))


# --- requests ------------------------------------------------------------------------------

def _request_form_context(values=None, errors=None):
    open_orders = (MaintenanceRecord.query.filter(MaintenanceRecord.status.in_(OPEN_STATUSES))
                   .outerjoin(Game).order_by(MaintenanceRecord.date_reported.desc()).all())
    return {"items": InventoryItem.query.order_by(InventoryItem.name.asc()).all(),
            "open_orders": open_orders, "urgencies": inv.URGENCIES,
            "values": values or {}, "errors": errors or {}}


@inventory_bp.route("/request", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def request_inventory():
    if request.method == "GET":
        values = {"item_type": "existing", "urgency": "Normal",
                  "item_id": request.args.get("item_id", ""),
                  "maintenance_id": request.args.get("maintenance_id", "")}
        return render_template("request_inventory.html", **_request_form_context(values))

    form = request.form
    errors = {}
    item = None
    # The page sends item_id="new" for a part we don't stock; older clients sent item_type.
    item_type = form.get("item_type") or (
        "existing" if form.get("item_id") not in (None, "", "new") else "new")
    if item_type == "existing":
        item_id = form.get("item_id", type=int)
        item = db.session.get(InventoryItem, item_id) if item_id else None
        if item is None:
            errors["item_id"] = "Pick a part from the list, or choose “A part we don’t stock”."
    item_name = form.get("item_name", "").strip()
    if item_type != "existing" and not item_name:
        errors["item_name"] = "Name the part."
    elif len(item_name) > 200:
        errors["item_name"] = "Keep the name under 200 characters."
    quantity = form.get("quantity", type=int)
    if not quantity or quantity <= 0:
        errors["quantity"] = "Ask for at least 1."
    maintenance_id = form.get("maintenance_id", type=int)
    if maintenance_id and db.session.get(MaintenanceRecord, maintenance_id) is None:
        errors["maintenance_id"] = "That work order no longer exists."
    if errors:
        values = dict(form, item_type=item_type)
        return render_template("request_inventory.html",
                               **_request_form_context(values, errors)), 400

    req = inv.create_request(item=item, item_name=item_name, quantity=quantity,
                             reason=form.get("reason", "").strip(),
                             urgency=form.get("urgency", "Normal"),
                             maintenance_id=maintenance_id, user_id=current_user.id)
    db.session.commit()
    flash(f'Requested {quantity} × "{req.item_name}".', "success")
    return redirect(url_for("inventory.inventory_requests_list"))


@inventory_bp.route("/requests")
@login_required
@requires_role("operator")
def inventory_requests_list():
    everything = inv.requests_visible_to(current_user).all()
    pending = sorted((r for r in everything if r.status == "Pending"),
                     key=lambda r: inv.URGENCY_RANK.get(r.urgency, 9))
    return render_template("inventory_requests.html", pending_requests=pending,
                           all_requests=everything, statuses=inv.REQUEST_STATUSES)


@inventory_bp.route("/requests/<int:request_id>")
@login_required
@requires_role("operator")
def inventory_request_detail(request_id):
    req = db.get_or_404(InventoryRequest, request_id)
    if not inv.can_view_request(current_user, req):
        flash("You can only view your own requests.", "error")
        return redirect(url_for("inventory.inventory_requests_list"))
    tracking = inv.tracking_events(req)
    return render_template("inventory_request_detail.html", req=req, history=req.history,
                           tracking=tracking, statuses=inv.REQUEST_STATUSES,
                           tracking_text=inv.TRACKING_TEXT, tracking_tone=inv.TRACKING_TONE,
                           can_delete=inv.can_delete_request(current_user, req))


@inventory_bp.route("/requests/<int:request_id>/update", methods=["POST"])
@login_required
@requires_role("manager")
def update_inventory_request(request_id):
    req = db.get_or_404(InventoryRequest, request_id)
    messages = inv.update_request(req, request.form, current_user.id)
    db.session.commit()
    for category, message in messages:
        flash(message, category)
    target = request.form.get("next")
    if target == "detail":
        return redirect(url_for("inventory.inventory_request_detail", request_id=req.id))
    return redirect(url_for("inventory.inventory_requests_list"))


@inventory_bp.route("/requests/<int:request_id>/delete", methods=["POST"])
@login_required
@requires_role("operator")
def delete_inventory_request(request_id):
    req = db.get_or_404(InventoryRequest, request_id)
    if not inv.can_delete_request(current_user, req):
        if req.requested_by_id != current_user.id:
            flash("You can only delete your own requests.", "error")
        else:
            flash("Only pending requests can be deleted.", "error")
        return redirect(url_for("inventory.inventory_requests_list"))
    name, status = req.item_name, req.status
    db.session.delete(req)
    db.session.commit()
    flash(f'Deleted the request for "{name}" ({status}).', "success")
    return redirect(url_for("inventory.inventory_requests_list"))


@inventory_bp.route("/requests/<int:request_id>/update_tracking", methods=["POST"])
@login_required
@requires_role("manager")
def update_request_tracking(request_id):
    req = db.get_or_404(InventoryRequest, request_id)
    back = redirect(url_for("inventory.inventory_request_detail", request_id=req.id))
    if not req.tracking_number:
        flash("No tracking number available for this request.", "error")
        return back
    api_key = os.getenv("EASYPOST_API_KEY")
    if not api_key or api_key == "your-easypost-api-key-here":
        flash("Tracking API not configured. Add EASYPOST_API_KEY to the .env file.", "warning")
        return back
    try:
        status = inv.refresh_tracking(req, api_key, current_user.id)
        db.session.commit()
    except ImportError:
        flash("The easypost package is not installed on the server.", "error")
    except Exception as e:  # noqa: BLE001 -- any carrier or network failure is reported
        db.session.rollback()
        flash(f"Could not fetch tracking: {e}", "error")
        log_security_event("TRACKING_UPDATE_FAILED", user_id=current_user.id,
                           details=f"Request #{req.id}, Error: {e}")
    else:
        flash(f"Tracking updated: {status}.", "success")
    return back
