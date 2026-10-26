"""Purchasing (inventory step 3): what to buy, what's on order, and receiving it.

The shopping list is every part at or below its reorder level. Its suggested quantity tops
the part up to its "order up to" level (twice the reorder level when that's blank), less
what is already on order, rounded up to whole packs. "On order" is what open requests and
open purchase orders still have to deliver.

Receiving puts stock into a place, through ``stock_places``, and can happen in pieces. A
price paid on delivery becomes the supplier's price (logged); the part's own unit price
changes only when asked. Purchase orders are a setting, off unless a manager turns them on.
Callers commit.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.extensions import db
from app.models import (
    InventoryItem,
    InventoryRequest,
    PurchaseOrder,
    PurchaseOrderLine,
    Setting,
    StockPlace,
    Supplier,
)
from app.models.parts import PO_OPEN
from app.services import parts, stock_places

PO_SETTING = "purchase_orders"
# Requests not yet closed still count as on order (Pending ones too: someone asked for them).
OPEN_REQUEST = ("Pending", "Approved", "Ordered", "Shipped")


class PurchasingError(ValueError):
    """A change that can't be made; the message is for the person who asked."""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def orders_enabled() -> bool:
    return Setting.get(PO_SETTING) == "on"


def set_orders_enabled(on: bool) -> None:
    Setting.put(PO_SETTING, "on" if on else "off")


# --- what's on order, and what to buy ------------------------------------------------------

def request_outstanding(req: InventoryRequest) -> int:
    return max(0, req.quantity_requested - (req.quantity_received or 0))


def on_order(item: InventoryItem) -> int:
    # Queried, not read from item.requests: a request made earlier in this request sets
    # item_id, which the loaded relationship doesn't see.
    requests = InventoryRequest.query.filter(InventoryRequest.item_id == item.id,
                                             InventoryRequest.status.in_(OPEN_REQUEST))
    lines = (PurchaseOrderLine.query.join(PurchaseOrder)
             .filter(PurchaseOrderLine.item_id == item.id, PurchaseOrder.status.in_(PO_OPEN)))
    return (sum(request_outstanding(r) for r in requests)
            + sum(line.outstanding for line in lines))


def target(item: InventoryItem) -> int:
    if item.reorder_to:
        return item.reorder_to
    return max((item.minimum_stock or 0) * 2, (item.minimum_stock or 0) + 1)


def suggested(item: InventoryItem, already: int | None = None) -> int:
    """How many to buy: up to the target, less what's coming, in whole packs. Parts reserved
    for open work orders don't count as in stock (inventory step 6)."""
    from app.services.reservations import available

    coming = on_order(item) if already is None else already
    need = target(item) - available(item) - coming
    if need <= 0:
        return 0
    pack = item.pack_size or 1
    return math.ceil(need / pack) * pack


@dataclass
class ShoppingRow:
    item: InventoryItem
    on_order: int
    suggest: int
    price: float | None          # per unit, from the preferred supplier (else our price)


@dataclass
class ShoppingGroup:
    supplier: Supplier | None
    rows: list[ShoppingRow] = field(default_factory=list)

    @property
    def total(self) -> float:
        return sum((r.price or 0) * r.suggest for r in self.rows)


def shopping_list() -> list[ShoppingGroup]:
    """Parts at or below their reorder level, grouped by preferred supplier; what's reserved
    for open work orders doesn't count as in stock. A part with no reorder level (0) is never
    on it."""
    from app.services.reservations import available

    low = [i for i in InventoryItem.query.filter(InventoryItem.minimum_stock > 0)
           .order_by(InventoryItem.name).all() if available(i) <= i.minimum_stock]
    groups: dict[int | None, ShoppingGroup] = {}
    for item in low:
        link = parts.preferred(item)
        coming = on_order(item)
        price = link.unit_cost if link and link.price is not None else (item.unit_price or None)
        key = link.supplier_id if link else None
        group = groups.setdefault(key, ShoppingGroup(link.supplier if link else None))
        group.rows.append(ShoppingRow(item, coming, suggested(item, coming), price))
    named = sorted((g for k, g in groups.items() if k is not None),
                   key=lambda g: g.supplier.name.lower())
    return named + ([groups[None]] if None in groups else [])


# --- receiving ----------------------------------------------------------------------------

def default_place(item: InventoryItem) -> StockPlace:
    """Where a delivery goes unless someone says: where most of the part already is."""
    held = [lv for lv in item.levels if lv.quantity and not lv.place.archived]
    if held:
        return max(held, key=lambda lv: lv.quantity).place
    return stock_places.unsorted_place()


def _received_price(item, supplier, price, user_id, why, update_item_price):
    if price is None:
        return
    if supplier is not None:
        link = parts.link_for(item, supplier)
        old = link.price
        link.price = price * (link.pack_size or 1)
        parts._log(item, old, link.price, user_id, why, supplier)
    if update_item_price:
        parts.set_item_price(item, price, user_id, why)


def receive_request(req: InventoryRequest, quantity: int, place: StockPlace | None,
                    user_id: int, price: float | None = None,
                    update_item_price: bool = False) -> str:
    """Put *quantity* of a request's delivery into *place*. Returns what happened, for a
    flash. The request is Received once everything has come; until then it stays as it was
    and shows as partly received."""
    from app.services.inventory import _history

    if req.status in ("Received", "Rejected"):
        raise PurchasingError(f"Request #{req.id} is {req.status}; nothing more to receive.")
    if quantity <= 0:
        raise PurchasingError("Receive at least one.")
    item = req.item
    if item is None:
        item = InventoryItem(name=req.item_name, stock_quantity=0, minimum_stock=5,
                             unit_price=0.0)
        db.session.add(item)
        db.session.flush()
        req.item_id, req.item = item.id, item
    place = place or default_place(item)
    stock_places.add(item, quantity, user_id, place, f"Request #{req.id} received")
    supplier = parts.find_supplier(req.vendor) if req.vendor else None
    _received_price(item, supplier, price, user_id, f"Paid on request #{req.id}",
                    update_item_price)
    req.quantity_received = (req.quantity_received or 0) + quantity
    _history(req, user_id, "received", notes=f"{quantity} received into {place.path}")
    if req.quantity_received >= req.quantity_requested:
        _history(req, user_id, "status_changed", field_changed="status",
                 old_value=req.status, new_value="Received")
        req.status = "Received"
        req.date_fulfilled = datetime.now(UTC)
        return (f"Request #{req.id} received: {quantity} into {place.path}. "
                f"In stock now: {item.stock_quantity}.")
    return (f"{quantity} of {req.quantity_requested} received into {place.path}; "
            f"{request_outstanding(req)} still to come.")


# --- requests from the shopping list ------------------------------------------------------

def request_from_list(item: InventoryItem, quantity: int, user_id: int) -> InventoryRequest:
    """A manager's request from the shopping list: already approved, for the preferred
    supplier."""
    from app.services.inventory import _history, create_request

    req = create_request(item=item, item_name=item.name, quantity=quantity,
                         reason="Shopping list", urgency="Normal", maintenance_id=None,
                         user_id=user_id)
    link = parts.preferred(item)
    if link is not None:
        req.vendor = link.supplier.name
    _history(req, user_id, "status_changed", field_changed="status", old_value="Pending",
             new_value="Approved")
    req.status = "Approved"
    return req


# --- purchase orders ----------------------------------------------------------------------

def draft_order(supplier: Supplier, user_id: int) -> PurchaseOrder:
    order = PurchaseOrder(supplier=supplier, status="Draft", created_by_id=user_id)
    db.session.add(order)
    db.session.flush()
    return order


def open_draft(supplier: Supplier, user_id: int) -> PurchaseOrder:
    """The supplier's current draft, or a new one: lines from the shopping list collect on
    one order per supplier until it is sent."""
    draft = (PurchaseOrder.query.filter_by(supplier_id=supplier.id, status="Draft")
             .order_by(PurchaseOrder.id.desc()).first())
    return draft or draft_order(supplier, user_id)


def add_line(order: PurchaseOrder, item: InventoryItem, quantity: int,
             unit_price: float | None = None) -> PurchaseOrderLine:
    if order.status != "Draft":
        raise PurchasingError(f"Order #{order.id} has been sent; start a new one instead.")
    if quantity <= 0:
        raise PurchasingError("Order at least one.")
    if unit_price is None:
        link = next((lk for lk in item.suppliers if lk.supplier_id == order.supplier_id), None)
        unit_price = link.unit_cost if link and link.price is not None else None
    for line in order.lines:
        if line.item_id == item.id:
            line.quantity += quantity
            return line
    line = PurchaseOrderLine(order=order, item=item, quantity=quantity, unit_price=unit_price)
    db.session.add(line)
    return line


def edit_line(line: PurchaseOrderLine, quantity: int, unit_price: float | None) -> None:
    if line.order.status != "Draft":
        raise PurchasingError("Only a draft's lines can be changed.")
    if quantity <= 0:
        raise PurchasingError("Order at least one, or remove the line.")
    line.quantity, line.unit_price = quantity, unit_price


def remove_line(line: PurchaseOrderLine) -> None:
    if line.order.status != "Draft":
        raise PurchasingError("Only a draft's lines can be removed.")
    line.order.lines.remove(line)
    db.session.delete(line)


def send(order: PurchaseOrder) -> None:
    if order.status != "Draft":
        raise PurchasingError(f"Order #{order.id} is already {order.status.lower()}.")
    if not order.lines:
        raise PurchasingError("Add a part before sending the order.")
    order.status, order.sent = "Sent", _now()


def cancel(order: PurchaseOrder) -> None:
    if not order.is_open:
        raise PurchasingError(f"Order #{order.id} is already {order.status.lower()}.")
    if any(line.quantity_received for line in order.lines):
        raise PurchasingError("Part of this order has arrived; it can't be cancelled. "
                              "Close it instead.")
    order.status, order.closed = "Cancelled", _now()


def close(order: PurchaseOrder) -> None:
    """Close an order that won't be filled any further (the rest is back-ordered elsewhere,
    or not coming)."""
    if order.status not in ("Sent", "Partly received"):
        raise PurchasingError("Only a sent order can be closed.")
    order.status, order.closed = "Received", _now()


def receive_line(line: PurchaseOrderLine, quantity: int, place: StockPlace | None,
                 user_id: int, price: float | None = None,
                 update_item_price: bool = False) -> str:
    order = line.order
    if order.status not in ("Sent", "Partly received"):
        raise PurchasingError("Send the order before receiving it." if order.status == "Draft"
                              else f"Order #{order.id} is {order.status.lower()}.")
    if quantity <= 0:
        raise PurchasingError("Receive at least one.")
    item = line.item
    place = place or default_place(item)
    stock_places.add(item, quantity, user_id, place, f"Purchase order #{order.id}")
    if price is not None:
        line.unit_price = price
    _received_price(item, order.supplier, price, user_id, f"Paid on order #{order.id}",
                    update_item_price)
    line.quantity_received = (line.quantity_received or 0) + quantity
    if all(ln.outstanding == 0 for ln in order.lines):
        order.status, order.closed = "Received", _now()
    else:
        order.status = "Partly received"
    extra = (f" ({line.quantity_received - line.quantity} more than ordered)"
             if line.quantity_received > line.quantity else "")
    return f"{quantity} {item.name} into {place.path}{extra}."
