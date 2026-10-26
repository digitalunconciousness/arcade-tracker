"""Inventory: parts in stock, adjustments, part requests and their shipments."""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import joinedload

from app.extensions import db
from app.models import (
    Game,
    InventoryItem,
    InventoryRequest,
    InventoryRequestHistory,
    LowStockAlert,
    StockHistory,
)
from app.services.stock import check_low_stock_alert

ADJUSTMENTS = {
    "added": "Stock added",
    "removed": "Stock removed",
    "used": "Used in a repair",
    "adjusted": "Counted (set to)",
    "damaged": "Damaged / written off",
    "returned": "Returned to supplier",
    "moved": "Moved",
}
REQUEST_STATUSES = ("Pending", "Approved", "Ordered", "Shipped", "Received", "Rejected")
URGENCIES = ("Low", "Normal", "High", "Urgent")
CLOSED_REQUEST = ("Received", "Rejected")
URGENCY_RANK = {"Urgent": 0, "High": 1, "Normal": 2, "Low": 3}


def is_manager(user) -> bool:
    return user.has_role("manager")


# --- items ---------------------------------------------------------------------------------

@dataclass
class ItemList:
    items: list[InventoryItem]
    low_count: int
    total_value: float
    my_pending: int
    recent_requests: list[InventoryRequest]


def list_items(user, search: str = "", low_only: bool = False,
               category_id: int | None = None) -> ItemList:
    """The parts list. *category_id* 0 means "no category"; None means every category."""
    query = InventoryItem.query
    if category_id == 0:
        query = query.filter(InventoryItem.category_id.is_(None))
    elif category_id is not None:
        query = query.filter(InventoryItem.category_id == category_id)
    if search:
        like = f"%{search}%"
        query = query.filter(InventoryItem.name.ilike(like)
                             | InventoryItem.description.ilike(like)
                             | InventoryItem.part_number.ilike(like)
                             | InventoryItem.supplier.ilike(like))
    if low_only:
        query = query.filter(InventoryItem.stock_quantity <= InventoryItem.minimum_stock)
    everything = InventoryItem.query.all()
    return ItemList(
        items=query.order_by(InventoryItem.name.asc()).all(),
        low_count=sum(1 for i in everything if i.is_low_stock()),
        total_value=sum(i.total_value() for i in everything),
        my_pending=InventoryRequest.query.filter_by(requested_by_id=user.id,
                                                    status="Pending").count(),
        recent_requests=requests_visible_to(user).limit(5).all(),
    )


def adjust_stock(item: InventoryItem, kind: str, quantity: int, reason: str,
                 user_id: int, place=None, to_place=None) -> tuple[int, int]:
    """Apply one adjustment in *place* and log it. Returns the total (before, after). Caller
    commits. Raises ``stock_places.StockError`` for a change that can't be made.

    added: plus quantity (into Unsorted when no place is given). removed / used / damaged /
    returned: minus quantity, never below zero; from *place*, or from wherever the part is.
    adjusted: a count of *place*, so that place is set to quantity; with no place, the total
    is set, as before places.
    moved: quantity from *place* to *to_place*; the total doesn't change.
    """
    from app.services import stock_places

    before = item.stock_quantity or 0
    if kind == "moved":
        if place is None or to_place is None:
            raise stock_places.StockError("Say where it is now and where it's going.")
        stock_places.move(item, quantity, user_id, place, to_place, reason)
    elif kind == "added":
        stock_places.add(item, quantity, user_id, place, reason or "Manual added")
    elif kind == "adjusted" and place is None:
        # A count with no place (a form from before places): the total, as it always was.
        stock_places.set_total(item, quantity, user_id, reason or "Manual adjusted")
    elif kind == "adjusted":
        stock_places.count(item, quantity, user_id, place, reason or "Manual adjusted")
    elif place is not None:
        stock_places.take(item, quantity, user_id, place, reason or f"Manual {kind}", kind)
    elif before:
        stock_places.take_anywhere(item, min(quantity, before), user_id,
                                   reason or f"Manual {kind}", kind)
    return before, item.stock_quantity or 0


def save_item(item: InventoryItem, form, user_id: int) -> None:
    """Copy the form onto *item* (new or existing) and log any stock change. Caller commits."""
    is_new = item.id is None
    before = 0 if is_new else (item.stock_quantity or 0)
    item.name = form.name.data.strip()
    item.part_number = form.part_number.data or None
    item.description = form.description.data or None
    from app.services import parts

    parts.set_item_price(item, float(form.unit_price.data or 0) or None, user_id)
    item.minimum_stock = form.minimum_stock.data
    item.reorder_to = form.reorder_to.data or None
    item.category_id = form.category.data or None
    item.unit = parts.clean_unit(form.unit.data)
    item.pack_size = parts.clean_pack(form.pack_size.data)
    item.serialized = bool(form.serialized.data)
    item.notes = form.notes.data or None
    item.compatible_games = (Game.query.filter(Game.id.in_(form.compatible_games.data)).all()
                             if form.compatible_games.data else [])
    from app.services import stock_places

    after = form.stock_quantity.data
    if is_new:
        item.stock_quantity = 0
        db.session.add(item)
        db.session.flush()
        parts.first_price(item, user_id)
    # The supplier box names the preferred supplier; a new name joins the supplier list.
    parts.set_preferred(item, parts.supplier_for(form.supplier.data))
    if is_new:
        if after:
            stock_places.add(item, after, user_id, reason="Initial stock")
        return
    if after != before:
        stock_places.set_total(item, after, user_id, "Manual adjustment via edit")
    else:
        check_low_stock_alert(item)


def item_history(item: InventoryItem, limit: int = 15) -> list[StockHistory]:
    return (StockHistory.query.options(joinedload(StockHistory.user))
            .filter_by(item_id=item.id)
            .order_by(StockHistory.timestamp.desc(), StockHistory.id.desc())
            .limit(limit).all())


def delete_item(item: InventoryItem) -> str | None:
    """Delete *item*. Returns why not, or None. Caller commits.

    A part used in a work order is kept, because the order's parts cost points at it
    (PostgreSQL refused this delete with an FK error, F-39). Its alerts go with it, and any
    requests for it keep their item name but lose the link.
    """
    if item.maintenance_usage:
        return (f'"{item.name}" was used in {len(item.maintenance_usage)} work order(s), '
                "so it stays for their parts history. Set its stock to 0 instead.")
    if item.order_lines:
        return (f'"{item.name}" is on {len(item.order_lines)} purchase order line(s), so it '
                "stays for their history. Set its stock to 0 instead.")
    for alert in item.alerts:
        db.session.delete(alert)
    for req in item.requests:
        req.item_id = None
    db.session.delete(item)
    return None


def alerts() -> tuple[list[LowStockAlert], list[LowStockAlert]]:
    """Active low-stock alerts, and those resolved in the last 30 days."""
    base = LowStockAlert.query.options(joinedload(LowStockAlert.item))
    active = (base.filter_by(resolved=False)
              .order_by(LowStockAlert.alert_triggered.desc()).all())
    since = datetime.now(dt.UTC).replace(tzinfo=None) - dt.timedelta(days=30)
    resolved = (base.filter(LowStockAlert.resolved.is_(True),
                            LowStockAlert.resolved_date >= since)
                .order_by(LowStockAlert.resolved_date.desc()).all())
    return active, resolved


# --- requests ------------------------------------------------------------------------------

def requests_visible_to(user):
    """Managers see every request; everyone else sees their own."""
    query = InventoryRequest.query.options(joinedload(InventoryRequest.requested_by))
    if not is_manager(user):
        query = query.filter_by(requested_by_id=user.id)
    return query.order_by(InventoryRequest.date_requested.desc())


def can_view_request(user, req: InventoryRequest) -> bool:
    return is_manager(user) or req.requested_by_id == user.id


def can_delete_request(user, req: InventoryRequest) -> bool:
    return is_manager(user) or (req.requested_by_id == user.id and req.status == "Pending")


def _history(req, user_id, action, **fields):
    db.session.add(InventoryRequestHistory(request_id=req.id, user_id=user_id, action=action,
                                           **fields))


def create_request(*, item: InventoryItem | None, item_name: str, quantity: int, reason: str,
                   urgency: str, maintenance_id: int | None, user_id: int) -> InventoryRequest:
    req = InventoryRequest(
        item_id=item.id if item else None,
        item_name=item.name if item else item_name,
        quantity_requested=quantity, reason=reason,
        urgency=urgency if urgency in URGENCIES else "Normal",
        requested_by_id=user_id, maintenance_id=maintenance_id)
    db.session.add(req)
    db.session.flush()
    _history(req, user_id, "created", notes=f"Request created for {req.item_name} (Qty: {quantity})")
    return req


def update_request(req: InventoryRequest, form, user_id: int) -> list[tuple[str, str]]:
    """Apply a manager's update. Returns flash messages. Caller commits.

    Two old bugs fixed here (F-9): stock is added only on the *change* to Received, not every
    time a received request is saved again; and a form with no status keeps the old one
    instead of blanking it.
    """
    messages: list[tuple[str, str]] = []
    new_status = form.get("status") or req.status
    if new_status not in REQUEST_STATUSES:
        return [("error", "Pick a status from the list.")]
    became_received = new_status == "Received" and req.status != "Received"

    if new_status != req.status:
        _history(req, user_id, "status_changed", field_changed="status",
                 old_value=req.status, new_value=new_status)
        req.status = new_status
        if new_status in CLOSED_REQUEST:
            req.date_fulfilled = datetime.now(dt.UTC)

    notes = form.get("notes", "").strip()
    if notes and notes != (req.notes or ""):
        _history(req, user_id, "notes_updated", field_changed="notes", notes=notes)
        req.notes = notes
    for field_name, action in (("tracking_number", "tracking_updated"),
                               ("vendor", "vendor_updated")):
        value = form.get(field_name, "").strip()
        if value and value != (getattr(req, field_name) or ""):
            _history(req, user_id, action, field_changed=field_name,
                     old_value=getattr(req, field_name), new_value=value)
            setattr(req, field_name, value)

    eta = form.get("estimated_arrival", "").strip()
    current_eta = req.estimated_arrival.strftime("%Y-%m-%d") if req.estimated_arrival else ""
    if eta and eta != current_eta:
        try:
            new_eta = dt.date.fromisoformat(eta)
        except ValueError:
            messages.append(("error", "The arrival date must look like 2026-10-20."))
        else:
            _history(req, user_id, "eta_updated", field_changed="estimated_arrival",
                     old_value=current_eta or None, new_value=str(new_eta))
            req.estimated_arrival = new_eta

    if became_received:
        messages.append(_receive(req, user_id))
    else:
        messages.append(("success", f'Request #{req.id} updated to "{req.status}"'))
    return messages


def _receive(req: InventoryRequest, user_id: int) -> tuple[str, str]:
    """Marked Received from the status list: put what hasn't arrived yet into stock, in the
    place most of the part already is (creating the item if it is new). A delivery that comes
    in pieces is received from the request's page instead (``purchasing.receive_request``)."""
    from app.services import purchasing, stock_places

    remaining = req.quantity_requested - (req.quantity_received or 0)
    req.quantity_received = req.quantity_requested
    if req.item_id:
        item = db.session.get(InventoryItem, req.item_id)
        if item is None:
            return ("error", (f"Request #{req.id} is Received, but item #{req.item_id} no "
                              "longer exists, so no stock was added."))
        if remaining <= 0:
            return ("success", f"Request #{req.id} received; everything had already arrived.")
        stock_places.add(item, remaining, user_id, purchasing.default_place(item),
                         reason=f"Inventory request #{req.id} received")
        return ("success", (f"Request #{req.id} received: {remaining} added to "
                            f'"{item.name}". In stock now: {item.stock_quantity}.'))
    item = InventoryItem(name=req.item_name, stock_quantity=0, unit_price=0.0,
                         minimum_stock=5)
    db.session.add(item)
    db.session.flush()
    req.item_id = item.id
    if remaining > 0:
        stock_places.add(item, remaining, user_id,
                         reason=f"New item created from inventory request #{req.id}")
    return ("success", (f'Request #{req.id} received: created "{item.name}" with '
                        f"{max(remaining, 0)} in stock. Add its price and details."))


# --- shipments (EasyPost) ------------------------------------------------------------------

TRACKING_TEXT = {
    "unknown": "Tracking information not yet available",
    "pre_transit": "Label created, waiting for carrier pickup",
    "in_transit": "Package is in transit",
    "out_for_delivery": "Out for delivery today",
    "delivered": "Package delivered",
    "available_for_pickup": "Available for pickup",
    "return_to_sender": "Package being returned to sender",
    "failure": "Delivery issue: check tracking details",
    "cancelled": "Shipment cancelled",
    "error": "Tracking error",
}
TRACKING_TONE = {"delivered": "ok", "available_for_pickup": "ok", "out_for_delivery": "info",
                 "in_transit": "info", "pre_transit": "muted", "failure": "fault",
                 "return_to_sender": "warn", "cancelled": "muted", "error": "fault"}


def tracking_events(req: InventoryRequest) -> dict | None:
    """The stored EasyPost snapshot (saved since tracking was added, never shown until now)."""
    if not req.tracking_details:
        return None
    try:
        data = json.loads(req.tracking_details)
    except (TypeError, ValueError):
        return None
    data["tracking_details"] = list(reversed(data.get("tracking_details") or []))  # newest first
    return data


def refresh_tracking(req: InventoryRequest, api_key: str, user_id: int) -> str:
    """Ask EasyPost for the shipment's status and store it. Returns the human status.

    Raises on any EasyPost or network failure; the route reports it.
    """
    import easypost

    client = easypost.EasyPostClient(api_key=api_key)
    carrier = req.carrier or "USPS"
    tracker = client.tracker.create(tracking_code=req.tracking_number, carrier=carrier)

    req.tracking_status = tracker.status
    req.carrier = tracker.carrier or carrier
    req.last_tracking_update = datetime.now(dt.UTC)
    req.tracking_details = json.dumps({
        "status": tracker.status,
        "status_detail": tracker.status_detail,
        "est_delivery_date": str(tracker.est_delivery_date) if tracker.est_delivery_date else None,
        "public_url": tracker.public_url,
        "tracking_details": [
            {
                "datetime": str(d.datetime) if d.datetime else None,
                "status": d.status,
                "message": d.message,
                "tracking_location": (
                    {"city": d.tracking_location.city, "state": d.tracking_location.state}
                    if d.tracking_location else None),
            }
            for d in (tracker.tracking_details or [])
        ],
    })

    if tracker.est_delivery_date:
        try:
            new_eta = dt.date.fromisoformat(str(tracker.est_delivery_date)[:10])
        except ValueError:
            new_eta = None
        if new_eta and req.estimated_arrival != new_eta:
            _history(req, user_id, "tracking_auto_updated", field_changed="estimated_arrival",
                     old_value=str(req.estimated_arrival) if req.estimated_arrival else None,
                     new_value=str(new_eta),
                     notes=f"Updated from tracking API (Status: {tracker.status})")
            req.estimated_arrival = new_eta

    _history(req, user_id, "tracking_refreshed",
             notes=f"Tracking refreshed: {tracker.status} ({tracker.status_detail or 'No details'})")
    return TRACKING_TEXT.get(tracker.status, tracker.status_detail or tracker.status)
