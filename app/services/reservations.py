"""Parts set aside for open work orders (inventory step 6).

A reservation keeps the parts on the shelf and in stock, but spoken for: the part page shows
them, and the shopping list counts them as needed, so the next repair doesn't find the shelf
already promised. A reservation is used (taken out of stock against its order, through
``work_orders.use_parts``) or released; an order that closes releases what it never used.
Callers commit.
"""

from __future__ import annotations

from app.extensions import db
from app.models import InventoryItem, MaintenanceRecord, PartReservation, StockPlace
from app.services import stock_places
from app.services.work_orders import OPEN_STATUSES, use_parts


class ReservationError(ValueError):
    """A change that can't be made; the message is for the person who asked."""


def reserved(item: InventoryItem) -> int:
    return sum(r.quantity for r in item.reservations)


def available(item: InventoryItem) -> int:
    """In stock and not spoken for."""
    return (item.stock_quantity or 0) - reserved(item)


def reserve(order: MaintenanceRecord, item: InventoryItem, quantity: int, user_id: int | None,
            place: StockPlace | None = None, partial: bool = False) -> PartReservation | None:
    """Set *quantity* aside for *order*. More than is free is refused, or with *partial*
    (a maintenance task opening its order) whatever is free is reserved. None if nothing
    could be."""
    if order.status not in OPEN_STATUSES:
        raise ReservationError(f"Work order #{order.id} is closed.")
    if quantity <= 0:
        raise ReservationError("Reserve at least one.")
    free = available(item)
    if place is not None:
        stock_places.reconcile(item)
        level = stock_places.level_of(item, place)
        free = min(free, level.quantity if level else 0)
    if quantity > free:
        if not partial:
            where = f" in {place.path}" if place is not None else ""
            raise ReservationError(f"Only {max(free, 0)} {item.name} free{where}. Order the "
                                   "rest with “Order it”.")
        quantity = max(free, 0)
        if quantity == 0:
            return None
    for res in order.reservations:
        if res.item_id == item.id and res.place_id == (place.id if place else None):
            res.quantity += quantity
            return res
    res = PartReservation(order=order, item=item, place=place, quantity=quantity,
                          user_id=user_id)
    db.session.add(res)
    return res


def use(res: PartReservation, user_id: int) -> str:
    """Take the reserved parts out of stock against the order."""
    order, item = res.order, res.item
    row = (item.id, res.quantity, res.place_id) if res.place_id else (item.id, res.quantity)
    order.reservations.remove(res)              # delete-orphan: the row goes with it
    result = use_parts(order, [row], user_id, f"Used in Work Order #{order.id}")
    if result.warnings:
        raise ReservationError(result.warnings[0])
    return f"Used {res.quantity} {item.name} (${result.cost:.2f})."


def release(res: PartReservation) -> None:
    res.order.reservations.remove(res)          # delete-orphan: the row goes with it


def release_closed(order: MaintenanceRecord) -> int:
    """An order that closed gives back what it never used. Returns how many lines."""
    if order.status in OPEN_STATUSES or not order.reservations:
        return 0
    lines = list(order.reservations)
    for res in lines:
        release(res)
    return len(lines)
