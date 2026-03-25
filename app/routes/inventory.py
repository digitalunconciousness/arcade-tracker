"""Inventory blueprint — item management, stock tracking, requests, alerts."""

import json
import os
import datetime as dt
from datetime import datetime, date

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required

from app.extensions import db
from app.models import (
    Game,
    InventoryItem,
    InventoryRequest,
    InventoryRequestHistory,
    LowStockAlert,
    MaintenanceInventoryUsage,
    MaintenanceRecord,
    PlayRecord,
    StockHistory,
)
from app.forms.inventory import InventoryItemForm, StockAdjustmentForm
from app.utils.decorators import requires_role
from app.utils.helpers import allowed_file, compress_and_save_image, get_directory_size

inventory_bp = Blueprint("inventory", __name__, url_prefix="/inventory")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_low_stock_alert(item):
    """Check if item needs a low stock alert and create one if needed."""
    if item.is_low_stock():
        existing_alert = LowStockAlert.query.filter_by(
            item_id=item.id, resolved=False
        ).first()
        if not existing_alert:
            alert = LowStockAlert(item_id=item.id, email_sent=False)
            db.session.add(alert)
            db.session.commit()
    else:
        active_alerts = LowStockAlert.query.filter_by(
            item_id=item.id, resolved=False
        ).all()
        for alert in active_alerts:
            alert.resolved = True
            alert.resolved_date = datetime.now(dt.UTC)
        if active_alerts:
            db.session.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@inventory_bp.route("/")
@login_required
@requires_role("operator")
def inventory_list():
    """Display inventory items with search and filter options"""
    search = request.args.get("search", "")
    low_stock_only = request.args.get("low_stock", False, type=bool)

    query = InventoryItem.query

    if search:
        query = query.filter(
            InventoryItem.name.contains(search)
            | InventoryItem.description.contains(search)
            | InventoryItem.part_number.contains(search)
        )

    if low_stock_only:
        query = query.filter(
            InventoryItem.stock_quantity <= InventoryItem.minimum_stock
        )

    items = query.order_by(InventoryItem.name.asc()).all()

    low_stock_count = InventoryItem.query.filter(
        InventoryItem.stock_quantity <= InventoryItem.minimum_stock
    ).count()

    total_value = sum(item.total_value() for item in InventoryItem.query.all())

    pending_requests_count = 0
    if current_user.is_authenticated:
        pending_requests_count = InventoryRequest.query.filter_by(
            requested_by_id=current_user.id,
            status="Pending",
        ).count()

    if current_user.role in ["admin", "manager"]:
        recent_requests = (
            InventoryRequest.query.order_by(
                InventoryRequest.date_requested.desc()
            )
            .limit(10)
            .all()
        )
    else:
        recent_requests = (
            InventoryRequest.query.filter_by(requested_by_id=current_user.id)
            .order_by(InventoryRequest.date_requested.desc())
            .limit(10)
            .all()
        )

    return render_template(
        "inventory_list.html",
        items=items,
        search=search,
        low_stock_only=low_stock_only,
        low_stock_count=low_stock_count,
        total_value=total_value,
        pending_requests_count=pending_requests_count,
        recent_requests=recent_requests,
    )


@inventory_bp.route("/add", methods=["GET", "POST"])
@login_required
@requires_role("manager")
def add_inventory_item():
    """Add a new inventory item"""
    form = InventoryItemForm()

    games = Game.query.order_by(Game.name.asc()).all()
    form.compatible_games.choices = [(g.id, g.name) for g in games]

    if request.method == "POST":
        print(f"DEBUG: Form submitted - Method: POST")
        print(f"DEBUG: Form data: {dict(request.form)}")

    if form.validate_on_submit():
        item = InventoryItem(
            name=form.name.data,
            description=form.description.data,
            stock_quantity=form.stock_quantity.data,
            unit_price=form.unit_price.data,
            minimum_stock=form.minimum_stock.data,
            supplier=form.supplier.data,
            part_number=form.part_number.data,
            notes=form.notes.data,
            last_restocked=(
                datetime.now(dt.UTC) if form.stock_quantity.data > 0 else None
            ),
        )

        if form.compatible_games.data:
            compatible_games = Game.query.filter(
                Game.id.in_(form.compatible_games.data)
            ).all()
            item.compatible_games.extend(compatible_games)

        db.session.add(item)

        if form.stock_quantity.data > 0:
            stock_history = StockHistory(
                item=item,
                change_type="added",
                quantity_change=form.stock_quantity.data,
                previous_quantity=0,
                new_quantity=form.stock_quantity.data,
                reason="Initial stock",
                user_id=current_user.id,
            )
            db.session.add(stock_history)

        db.session.commit()

        flash(f'Inventory item "{item.name}" added successfully!', "success")
        return redirect(url_for("inventory.inventory_list"))
    elif request.method == "POST":
        print(f"DEBUG: Form errors: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{field}: {error}", "error")

    return render_template("add_inventory_item.html", form=form)


@inventory_bp.route("/<int:item_id>")
@login_required
@requires_role("operator")
def inventory_detail(item_id):
    """View detailed information about an inventory item"""
    item = InventoryItem.query.get_or_404(item_id)

    recent_history = (
        StockHistory.query.filter_by(item_id=item_id)
        .order_by(StockHistory.timestamp.desc())
        .limit(10)
        .all()
    )

    active_alert = LowStockAlert.query.filter_by(
        item_id=item_id, resolved=False
    ).first()

    return render_template(
        "inventory_detail.html",
        item=item,
        recent_history=recent_history,
        active_alert=active_alert,
    )


@inventory_bp.route("/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
@requires_role("manager")
def edit_inventory_item(item_id):
    """Edit an inventory item"""
    item = InventoryItem.query.get_or_404(item_id)
    form = InventoryItemForm(obj=item)

    games = Game.query.order_by(Game.name.asc()).all()
    form.compatible_games.choices = [(g.id, g.name) for g in games]

    if request.method == "GET":
        # Manually populate fields whose names differ from the model
        form.unit_price.data = item.unit_price
        form.part_number.data = item.part_number
        form.compatible_games.data = [g.id for g in item.compatible_games]

    if form.validate_on_submit():
        old_stock = item.stock_quantity

        item.name = form.name.data
        item.description = form.description.data
        item.stock_quantity = form.stock_quantity.data
        item.unit_price = form.unit_price.data
        item.minimum_stock = form.minimum_stock.data
        item.supplier = form.supplier.data
        item.part_number = form.part_number.data
        item.notes = form.notes.data

        item.compatible_games.clear()
        if form.compatible_games.data:
            compatible_games = Game.query.filter(
                Game.id.in_(form.compatible_games.data)
            ).all()
            item.compatible_games.extend(compatible_games)

        if old_stock != form.stock_quantity.data:
            quantity_change = form.stock_quantity.data - old_stock
            stock_history = StockHistory(
                item_id=item_id,
                change_type="adjusted",
                quantity_change=quantity_change,
                previous_quantity=old_stock,
                new_quantity=form.stock_quantity.data,
                reason="Manual adjustment via edit",
                user_id=current_user.id,
            )
            db.session.add(stock_history)

            if form.stock_quantity.data > old_stock:
                item.last_restocked = datetime.now(dt.UTC)

        db.session.commit()

        _check_low_stock_alert(item)

        flash(f'Inventory item "{item.name}" updated successfully!', "success")
        return redirect(url_for("inventory.inventory_detail", item_id=item_id))

    return render_template("edit_inventory_item.html", form=form, item=item)


@inventory_bp.route("/<int:item_id>/adjust_stock", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def adjust_stock(item_id):
    """Manually adjust stock levels for an inventory item"""
    item = InventoryItem.query.get_or_404(item_id)
    form = StockAdjustmentForm()

    if form.validate_on_submit():
        old_quantity = item.stock_quantity
        adjustment_type = form.reason.data
        quantity = form.quantity_change.data

        # Calculate new quantity based on adjustment type
        if adjustment_type in ["added"]:
            new_quantity = old_quantity + quantity
            quantity_change = quantity
        elif adjustment_type in ["removed", "used"]:
            new_quantity = max(0, old_quantity - quantity)
            quantity_change = -(min(quantity, old_quantity))
        else:  # adjusted - direct set
            new_quantity = quantity
            quantity_change = quantity - old_quantity

        item.stock_quantity = new_quantity
        if adjustment_type == "added":
            item.last_restocked = datetime.now(dt.UTC)

        stock_history = StockHistory(
            item_id=item_id,
            change_type=adjustment_type,
            quantity_change=quantity_change,
            previous_quantity=old_quantity,
            new_quantity=new_quantity,
            reason=form.notes.data or f"Manual {adjustment_type}",
            user_id=current_user.id,
        )

        db.session.add(stock_history)
        db.session.commit()

        _check_low_stock_alert(item)

        flash(
            f'Stock adjusted for "{item.name}": {old_quantity} → {new_quantity}',
            "success",
        )
        return redirect(url_for("inventory.inventory_detail", item_id=item_id))

    return render_template("adjust_stock.html", form=form, item=item)


@inventory_bp.route("/<int:item_id>/delete", methods=["POST"])
@login_required
@requires_role("admin")
def delete_inventory_item(item_id):
    """Delete an inventory item and all associated records"""
    item = InventoryItem.query.get_or_404(item_id)

    try:
        item_name = item.name
        db.session.delete(item)
        db.session.commit()

        flash(f'Inventory item "{item_name}" deleted successfully!', "success")
    except Exception as e:  # noqa: BLE001
        db.session.rollback()
        flash(f"Error deleting item: {str(e)}", "error")

    return redirect(url_for("inventory.inventory_list"))


@inventory_bp.route("/low_stock_alerts")
@login_required
@requires_role("manager")
def low_stock_alerts():
    """View and manage low stock alerts"""
    from datetime import timedelta

    active_alerts = (
        LowStockAlert.query.filter_by(resolved=False)
        .join(InventoryItem)
        .order_by(LowStockAlert.alert_triggered.desc())
        .all()
    )

    thirty_days_ago = date.today() - timedelta(days=30)
    recent_resolved = (
        LowStockAlert.query.filter(
            LowStockAlert.resolved == True,  # noqa: E712
            LowStockAlert.resolved_date >= thirty_days_ago,
        )
        .join(InventoryItem)
        .order_by(LowStockAlert.resolved_date.desc())
        .all()
    )

    return render_template(
        "low_stock_alerts.html",
        active_alerts=active_alerts,
        recent_resolved=recent_resolved,
    )


@inventory_bp.route("/resolve_alert/<int:alert_id>", methods=["POST"])
@login_required
@requires_role("manager")
def resolve_low_stock_alert(alert_id):
    """Mark a low stock alert as resolved"""
    alert = LowStockAlert.query.get_or_404(alert_id)

    alert.resolved = True
    alert.resolved_date = datetime.now(dt.UTC)
    db.session.commit()

    flash(
        f'Low stock alert for "{alert.item.name}" marked as resolved.',
        "success",
    )
    return redirect(url_for("inventory.low_stock_alerts"))


# =====================================
# INVENTORY REQUEST ROUTES
# =====================================

@inventory_bp.route("/request", methods=["GET", "POST"])
@login_required
@requires_role("operator")
def request_inventory():
    """Create a new inventory request"""
    if request.method == "POST":
        item_type = request.form.get("item_type")
        item_id = request.form.get("item_id")
        item_name = request.form.get("item_name")
        quantity = request.form.get("quantity", type=int)
        reason = request.form.get("reason", "")
        urgency = request.form.get("urgency", "Normal")
        maintenance_id = request.form.get("maintenance_id")

        if not item_name or not quantity or quantity <= 0:
            flash("Please provide valid item name and quantity.", "error")
            return redirect(url_for("inventory.request_inventory"))

        inv_request = InventoryRequest(
            item_id=(
                int(item_id) if item_type == "existing" and item_id else None
            ),
            item_name=item_name,
            quantity_requested=quantity,
            reason=reason,
            urgency=urgency,
            requested_by_id=current_user.id,
            maintenance_id=int(maintenance_id) if maintenance_id else None,
        )

        db.session.add(inv_request)
        db.session.flush()

        history = InventoryRequestHistory(
            request_id=inv_request.id,
            user_id=current_user.id,
            action="created",
            notes=f"Request created for {item_name} (Qty: {quantity})",
        )
        db.session.add(history)
        db.session.commit()

        flash(
            f'Request for "{item_name}" (Qty: {quantity}) submitted successfully!',
            "success",
        )
        return redirect(url_for("inventory.inventory_requests_list"))

    # GET request - show form
    existing_items = InventoryItem.query.order_by(InventoryItem.name.asc()).all()

    open_maintenance = (
        MaintenanceRecord.query.filter(
            MaintenanceRecord.status.in_(["Open", "In_Progress"])
        )
        .outerjoin(Game)
        .order_by(MaintenanceRecord.date_reported.desc())
        .all()
    )

    preselected_maintenance_id = request.args.get("maintenance_id", type=int)

    return render_template(
        "request_inventory.html",
        existing_items=existing_items,
        open_maintenance=open_maintenance,
        preselected_maintenance_id=preselected_maintenance_id,
    )


@inventory_bp.route("/requests")
@login_required
@requires_role("operator")
def inventory_requests_list():
    """View all inventory requests"""
    if current_user.role in ["admin", "manager"]:
        pending_requests = (
            InventoryRequest.query.filter_by(status="Pending")
            .order_by(
                InventoryRequest.urgency.desc(),
                InventoryRequest.date_requested.desc(),
            )
            .all()
        )
        all_requests = (
            InventoryRequest.query.order_by(
                InventoryRequest.date_requested.desc()
            ).all()
        )
    else:
        pending_requests = (
            InventoryRequest.query.filter_by(
                requested_by_id=current_user.id, status="Pending"
            )
            .order_by(InventoryRequest.date_requested.desc())
            .all()
        )
        all_requests = (
            InventoryRequest.query.filter_by(requested_by_id=current_user.id)
            .order_by(InventoryRequest.date_requested.desc())
            .all()
        )

    return render_template(
        "inventory_requests.html",
        pending_requests=pending_requests,
        all_requests=all_requests,
    )


@inventory_bp.route("/requests/<int:request_id>")
@login_required
@requires_role("operator")
def inventory_request_detail(request_id):
    """View detailed information and full audit history of an inventory request"""
    inv_request = InventoryRequest.query.get_or_404(request_id)

    if current_user.role not in ["admin", "manager"]:
        if inv_request.requested_by_id != current_user.id:
            flash("You can only view your own requests.", "error")
            return redirect(url_for("inventory.inventory_requests_list"))

    history = inv_request.history

    return render_template(
        "inventory_request_detail.html",
        request=inv_request,
        history=history,
    )


@inventory_bp.route("/requests/<int:request_id>/update", methods=["POST"])
@login_required
@requires_role("manager")
def update_inventory_request(request_id):
    """Update status of an inventory request"""
    inv_request = InventoryRequest.query.get_or_404(request_id)

    new_status = request.form.get("status")
    notes = request.form.get("notes", "")
    tracking_number = request.form.get("tracking_number", "")
    vendor = request.form.get("vendor", "")
    estimated_arrival = request.form.get("estimated_arrival", "")

    changes = []

    if inv_request.status != new_status:
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action="status_changed",
            field_changed="status",
            old_value=inv_request.status,
            new_value=new_status,
        )
        db.session.add(history)
        inv_request.status = new_status
        changes.append(f"Status: {inv_request.status} → {new_status}")

    if notes and notes != (inv_request.notes or ""):
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action="notes_updated",
            field_changed="notes",
            notes=notes,
        )
        db.session.add(history)
        inv_request.notes = notes

    if tracking_number and tracking_number != (inv_request.tracking_number or ""):
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action="tracking_updated",
            field_changed="tracking_number",
            old_value=inv_request.tracking_number,
            new_value=tracking_number,
        )
        db.session.add(history)
        inv_request.tracking_number = tracking_number
        changes.append(f"Tracking: {tracking_number}")

    if vendor and vendor != (inv_request.vendor or ""):
        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action="vendor_updated",
            field_changed="vendor",
            old_value=inv_request.vendor,
            new_value=vendor,
        )
        db.session.add(history)
        inv_request.vendor = vendor
        changes.append(f"Vendor: {vendor}")

    if estimated_arrival and estimated_arrival != (
        inv_request.estimated_arrival.strftime("%Y-%m-%d")
        if inv_request.estimated_arrival
        else ""
    ):
        try:
            from datetime import datetime as dt_module

            new_eta = dt_module.strptime(estimated_arrival, "%Y-%m-%d").date()
            history = InventoryRequestHistory(
                request_id=request_id,
                user_id=current_user.id,
                action="eta_updated",
                field_changed="estimated_arrival",
                old_value=(
                    str(inv_request.estimated_arrival)
                    if inv_request.estimated_arrival
                    else None
                ),
                new_value=str(new_eta),
            )
            db.session.add(history)
            inv_request.estimated_arrival = new_eta
            changes.append(f"ETA: {new_eta}")
        except ValueError:
            pass

    if new_status in ["Received", "Rejected"]:
        inv_request.date_fulfilled = datetime.now(dt.UTC)

    # If status is "Received", add the quantity to inventory
    if new_status == "Received":
        if inv_request.item_id:
            item = InventoryItem.query.get(inv_request.item_id)
            if item:
                previous_qty = item.stock_quantity
                item.stock_quantity += inv_request.quantity_requested
                item.last_restocked = datetime.now(dt.UTC)

                stock_history = StockHistory(
                    item_id=item.id,
                    change_type="added",
                    quantity_change=inv_request.quantity_requested,
                    previous_quantity=previous_qty,
                    new_quantity=item.stock_quantity,
                    reason=f"Inventory request #{request_id} received",
                    user_id=current_user.id,
                )
                db.session.add(stock_history)

                _check_low_stock_alert(item)

                flash(
                    f"Request #{request_id} received! "
                    f'Added {inv_request.quantity_requested} units of "{item.name}" to inventory. '
                    f"New stock: {item.stock_quantity}",
                    "success",
                )
            else:
                flash(
                    f'Request #{request_id} updated to "{new_status}" '
                    f"but item ID {inv_request.item_id} not found in inventory.",
                    "error",
                )
        else:
            new_item = InventoryItem(
                name=inv_request.item_name,
                stock_quantity=inv_request.quantity_requested,
                unit_price=0.0,
                minimum_stock=5,
                last_restocked=datetime.now(dt.UTC),
            )
            db.session.add(new_item)
            db.session.flush()

            inv_request.item_id = new_item.id

            stock_history = StockHistory(
                item_id=new_item.id,
                change_type="added",
                quantity_change=inv_request.quantity_requested,
                previous_quantity=0,
                new_quantity=inv_request.quantity_requested,
                reason=f"New item created from inventory request #{request_id}",
                user_id=current_user.id,
            )
            db.session.add(stock_history)

            flash(
                f'Request #{request_id} received! Created new inventory item "{new_item.name}" '
                f"with {inv_request.quantity_requested} units. "
                "Please update pricing and details.",
                "success",
            )
    else:
        flash(f'Request #{request_id} updated to "{new_status}"', "success")

    db.session.commit()
    return redirect(url_for("inventory.inventory_requests_list"))


@inventory_bp.route("/requests/<int:request_id>/delete", methods=["POST"])
@login_required
@requires_role("operator")
def delete_inventory_request(request_id):
    """Delete an inventory request"""
    inv_request = InventoryRequest.query.get_or_404(request_id)

    if current_user.role in ["admin", "manager"]:
        pass
    else:
        if inv_request.status != "Pending":
            flash("Only pending requests can be deleted.", "error")
            return redirect(url_for("inventory.inventory_requests_list"))

        if inv_request.requested_by_id != current_user.id:
            flash("You can only delete your own requests.", "error")
            return redirect(url_for("inventory.inventory_requests_list"))

    item_name = inv_request.item_name
    request_status = inv_request.status
    db.session.delete(inv_request)
    db.session.commit()

    flash(
        f'Request for "{item_name}" (Status: {request_status}) deleted successfully.',
        "success",
    )
    return redirect(url_for("inventory.inventory_requests_list"))


@inventory_bp.route("/requests/<int:request_id>/update_tracking", methods=["POST"])
@login_required
@requires_role("manager")
def update_request_tracking(request_id):
    """Fetch and update shipment tracking information using EasyPost API"""
    inv_request = InventoryRequest.query.get_or_404(request_id)

    if not inv_request.tracking_number:
        flash("No tracking number available for this request.", "error")
        return redirect(
            url_for("inventory.inventory_request_detail", request_id=request_id)
        )

    api_key = os.getenv("EASYPOST_API_KEY")
    if not api_key or api_key == "your-easypost-api-key-here":
        flash(
            "Tracking API not configured. "
            "Please add EASYPOST_API_KEY to your .env file.",
            "warning",
        )
        return redirect(
            url_for("inventory.inventory_request_detail", request_id=request_id)
        )

    try:
        import easypost

        client = easypost.EasyPostClient(api_key=api_key)

        carrier = inv_request.carrier or "USPS"

        tracker = client.tracker.create(
            tracking_code=inv_request.tracking_number,
            carrier=carrier,
        )

        inv_request.tracking_status = tracker.status
        inv_request.carrier = tracker.carrier or carrier
        inv_request.last_tracking_update = datetime.now(dt.UTC)

        tracking_info = {
            "status": tracker.status,
            "status_detail": tracker.status_detail,
            "est_delivery_date": (
                str(tracker.est_delivery_date)
                if tracker.est_delivery_date
                else None
            ),
            "public_url": tracker.public_url,
            "tracking_details": [
                {
                    "datetime": (
                        str(detail.datetime) if detail.datetime else None
                    ),
                    "status": detail.status,
                    "message": detail.message,
                    "tracking_location": (
                        {
                            "city": (
                                detail.tracking_location.city
                                if detail.tracking_location
                                else None
                            ),
                            "state": (
                                detail.tracking_location.state
                                if detail.tracking_location
                                else None
                            ),
                        }
                        if detail.tracking_location
                        else None
                    ),
                }
                for detail in (tracker.tracking_details or [])
            ],
        }
        inv_request.tracking_details = json.dumps(tracking_info)

        if tracker.est_delivery_date:
            try:
                from datetime import datetime as dt_module

                new_eta = dt_module.strptime(
                    tracker.est_delivery_date, "%Y-%m-%d"
                ).date()
                if inv_request.estimated_arrival != new_eta:
                    history = InventoryRequestHistory(
                        request_id=request_id,
                        user_id=current_user.id,
                        action="tracking_auto_updated",
                        field_changed="estimated_arrival",
                        old_value=(
                            str(inv_request.estimated_arrival)
                            if inv_request.estimated_arrival
                            else None
                        ),
                        new_value=str(new_eta),
                        notes=f"Updated from tracking API (Status: {tracker.status})",
                    )
                    db.session.add(history)
                    inv_request.estimated_arrival = new_eta
            except (ValueError, AttributeError):
                pass

        history = InventoryRequestHistory(
            request_id=request_id,
            user_id=current_user.id,
            action="tracking_refreshed",
            notes=(
                f"Tracking refreshed: {tracker.status} "
                f"({tracker.status_detail or 'No details'})"
            ),
        )
        db.session.add(history)

        db.session.commit()

        status_messages = {
            "unknown": "Tracking information not yet available",
            "pre_transit": "Label created, waiting for carrier pickup",
            "in_transit": "Package is in transit",
            "out_for_delivery": "Out for delivery today",
            "delivered": "Package delivered!",
            "available_for_pickup": "Available for pickup",
            "return_to_sender": "Package being returned to sender",
            "failure": "Delivery issue - check tracking details",
            "cancelled": "Shipment cancelled",
            "error": "Tracking error",
        }

        status_msg = status_messages.get(
            tracker.status, tracker.status_detail or tracker.status
        )
        flash(f"Tracking updated! Status: {status_msg}", "success")

    except ImportError:
        flash(
            "EasyPost library not installed. Run: pip install easypost",
            "error",
        )
    except Exception as e:  # noqa: BLE001
        flash(f"Error fetching tracking info: {str(e)}", "error")
        try:
            from app.security.utils import log_security_event
        except ImportError:
            try:
                from security_utils import log_security_event
            except ImportError:
                log_security_event = None
        if log_security_event is not None:
            log_security_event(
                "TRACKING_UPDATE_FAILED",
                user_id=current_user.id,
                details=(
                    f"Request #{request_id}, "
                    f"Tracking: {inv_request.tracking_number}, "
                    f"Error: {str(e)}"
                ),
            )

    return redirect(
        url_for("inventory.inventory_request_detail", request_id=request_id)
    )
