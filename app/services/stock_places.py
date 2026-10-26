"""Where stock is, and changing it: the only code that touches a ``StockLevel``.

Every change is one of: add to a place, take from a place, count a place (set it), or move
between two places. Each keeps ``InventoryItem.stock_quantity`` equal to the sum of the
part's levels, writes a ``StockHistory`` row naming the place(s), and runs the low-stock
check. Callers commit.

History rows keep their old meaning: ``previous_quantity``/``new_quantity`` are the part's
total before and after, so the history list and reports read as they always have. A move
leaves the total alone; its ``quantity_change`` is the number moved.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from app.extensions import db
from app.models import InventoryItem, StockHistory, StockLevel, StockPlace
from app.models.stock import MAX_DEPTH, UNSORTED_CODE
from app.services.stock import check_low_stock_alert

# Kinds that take stock out, as the adjust form has always offered them.
TAKE_KINDS = ("removed", "used", "damaged", "returned")
MAX_NAME = 100


class StockError(ValueError):
    """A change that cannot be made; the message is for the person who asked."""


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def unsorted_place() -> StockPlace:
    """Where stock goes when nobody has said where (made by the migration; made here if a
    test or a fresh database has none)."""
    place = StockPlace.query.filter_by(code=UNSORTED_CODE).first()
    if place is None:
        place = StockPlace(name="Unsorted", code=UNSORTED_CODE)
        db.session.add(place)
        db.session.flush()
    return place


def reconcile(item: InventoryItem) -> None:
    """Make the levels add up to ``stock_quantity`` before a change, without logging it.

    Stock the places don't account for (set on the total by older code, a script, a test)
    is in Unsorted, which is what Unsorted means. If the places hold more than the total,
    the extra comes off Unsorted first, then the fullest place.
    """
    total = item.stock_quantity or 0
    held = sum(lv.quantity or 0 for lv in item.levels)
    if held < total:
        level_of(item, unsorted_place(), create=True).quantity += total - held
    elif held > total:
        extra = held - total
        for lv in sorted(item.levels, key=lambda lv: (not lv.place.is_unsorted, -lv.quantity)):
            cut = min(extra, lv.quantity or 0)
            lv.quantity -= cut
            extra -= cut
            if not extra:
                break


def level_of(item: InventoryItem, place: StockPlace, create: bool = False) -> StockLevel | None:
    level = StockLevel.query.filter_by(item_id=item.id, place_id=place.id).first()
    if level is None and create:
        level = StockLevel(item=item, place=place, quantity=0)
        db.session.add(level)
    return level


def _record(item, kind, change, before, reason, user_id, place, to_place=None):
    db.session.add(StockHistory(
        item_id=item.id, change_type=kind, quantity_change=change, previous_quantity=before,
        new_quantity=item.stock_quantity or 0, reason=(reason or "")[:200] or None,
        user_id=user_id, place_id=place.id if place else None,
        to_place_id=to_place.id if to_place else None))


def _check(item):
    check_low_stock_alert(item)


def _usable(place: StockPlace | None) -> StockPlace:
    if place is None:
        return unsorted_place()
    if place.archived:
        raise StockError(f"{place.path} is archived. Restore it first, or pick another place.")
    return place


def add(item: InventoryItem, quantity: int, user_id: int, place: StockPlace | None = None,
        reason: str = "", kind: str = "added") -> StockLevel:
    """Put *quantity* into *place* (Unsorted when none is given)."""
    if quantity <= 0:
        raise StockError("Add at least one.")
    reconcile(item)
    place = _usable(place)
    level = level_of(item, place, create=True)
    before = item.stock_quantity or 0
    level.quantity = (level.quantity or 0) + quantity
    item.stock_quantity = before + quantity
    item.last_restocked = datetime.now(UTC)
    _record(item, kind, quantity, before, reason or f"Added to {place.path}", user_id, place)
    _check(item)
    return level


def take(item: InventoryItem, quantity: int, user_id: int, place: StockPlace,
         reason: str = "", kind: str = "removed") -> int:
    """Take up to *quantity* from *place*. Returns how many were actually there to take."""
    if quantity <= 0:
        raise StockError("Take at least one.")
    reconcile(item)
    level = level_of(item, place)
    have = level.quantity if level else 0
    taken = min(quantity, have)
    if taken == 0:
        raise StockError(f"There are none of {item.name} in {place.path}.")
    before = item.stock_quantity or 0
    level.quantity = have - taken
    item.stock_quantity = before - taken
    _record(item, kind, -taken, before, reason or f"Taken from {place.path}", user_id, place)
    _check(item)
    return taken


def take_anywhere(item: InventoryItem, quantity: int, user_id: int, reason: str = "",
                  kind: str = "used") -> list[tuple[StockPlace, int]]:
    """Take *quantity* from wherever the part is, for callers that don't say where (a work
    order's parts, until it can pick a place). Unsorted first, then the fullest place.
    The caller has already checked the total covers it."""
    reconcile(item)
    levels = sorted((lv for lv in item.levels if lv.quantity > 0),
                    key=lambda lv: (not lv.place.is_unsorted, -lv.quantity))
    taken, left = [], quantity
    for level in levels:
        if left <= 0:
            break
        n = take(item, min(left, level.quantity), user_id, level.place, reason, kind)
        taken.append((level.place, n))
        left -= n
    return taken


def count(item: InventoryItem, quantity: int, user_id: int, place: StockPlace | None = None,
          reason: str = "") -> int:
    """Set *place*'s level to what was counted there. Returns the change."""
    if quantity < 0:
        raise StockError("A count can't be below zero.")
    reconcile(item)
    place = _usable(place)
    level = level_of(item, place, create=True)
    change = quantity - (level.quantity or 0)
    before = item.stock_quantity or 0
    level.quantity = quantity
    level.counted = _now()
    item.stock_quantity = before + change
    if change > 0:
        item.last_restocked = datetime.now(UTC)
    _record(item, "adjusted", change, before, reason or f"Counted in {place.path}", user_id,
            place)
    _check(item)
    return change


def move(item: InventoryItem, quantity: int, user_id: int, source: StockPlace,
         dest: StockPlace, reason: str = "") -> int:
    """Move up to *quantity* from *source* to *dest*. The total doesn't change."""
    if source.id == dest.id:
        raise StockError("Pick a different place to move it to.")
    if quantity <= 0:
        raise StockError("Move at least one.")
    reconcile(item)
    dest = _usable(dest)
    level = level_of(item, source)
    have = level.quantity if level else 0
    moved = min(quantity, have)
    if moved == 0:
        raise StockError(f"There are none of {item.name} in {source.path}.")
    level.quantity = have - moved
    target = level_of(item, dest, create=True)
    target.quantity = (target.quantity or 0) + moved
    before = item.stock_quantity or 0
    _record(item, "moved", moved, before, reason or f"{source.path} → {dest.path}", user_id,
            source, dest)
    return moved


def set_total(item: InventoryItem, quantity: int, user_id: int, reason: str) -> None:
    """The item form's "In stock" box, for a form that only knows the total: more goes into
    Unsorted, fewer comes out of wherever it is."""
    before = item.stock_quantity or 0
    if quantity > before:
        add(item, quantity - before, user_id, reason=reason, kind="adjusted")
    elif quantity < before:
        take_anywhere(item, before - quantity, user_id, reason=reason, kind="adjusted")


# --- places -------------------------------------------------------------------------------

@dataclass
class PlaceNode:
    place: StockPlace
    depth: int
    parts: int      # distinct parts here and below
    units: int      # units here and below


def place_tree(include_archived: bool = False) -> list[PlaceNode]:
    """Every place, depth first, Unsorted last, with what each holds (itself and below)."""
    places = StockPlace.query.all()
    by_parent: dict[int | None, list[StockPlace]] = {}
    for p in places:
        if include_archived or not p.archived:
            by_parent.setdefault(p.parent_id, []).append(p)
    held: dict[int, list[StockLevel]] = {}
    for lv in StockLevel.query.filter(StockLevel.quantity > 0).all():
        held.setdefault(lv.place_id, []).append(lv)

    out: list[PlaceNode] = []

    def walk(parent_id, depth):
        kids = sorted(by_parent.get(parent_id, []), key=lambda p: (p.is_unsorted, p.name.lower()))
        for p in kids:
            node = PlaceNode(p, depth, 0, 0)
            out.append(node)
            start = len(out)
            walk(p.id, depth + 1)
            mine = [lv for q in [p] + [n.place for n in out[start:]] for lv in held.get(q.id, [])]
            node.parts = len({lv.item_id for lv in mine})
            node.units = sum(lv.quantity for lv in mine)

    walk(None, 0)
    return out


def clean_name(name: str | None) -> str:
    name = " ".join((name or "").split())
    if not name:
        raise StockError("Give the place a name.")
    if len(name) > MAX_NAME:
        raise StockError(f"Keep the name to {MAX_NAME} characters.")
    return name


def check_parent(place: StockPlace | None, parent: StockPlace | None) -> None:
    """A place can't sit inside itself or its own contents, nor nest deeper than MAX_DEPTH."""
    if parent is None:
        return
    if place is not None and place.is_unsorted:
        raise StockError("Unsorted stays at the top.")
    if parent.is_unsorted:
        raise StockError("Places can't go inside Unsorted.")
    if place is not None and (parent.id == place.id or parent in place.descendants()):
        raise StockError("A place can't go inside itself.")
    below = max((len(d.lineage()) - len(place.lineage()) for d in place.descendants()),
                default=0) if place is not None else 0
    if len(parent.lineage()) + 1 + below > MAX_DEPTH:
        raise StockError(f"Places nest at most {MAX_DEPTH} deep.")


def sibling_taken(name: str, parent: StockPlace | None, place: StockPlace | None = None) -> bool:
    q = StockPlace.query.filter(StockPlace.parent_id == (parent.id if parent else None))
    return any(p.name.lower() == name.lower() and (place is None or p.id != place.id)
               for p in q.all())


def place_holds_stock(place: StockPlace) -> bool:
    ids = [place.id] + [p.id for p in place.descendants()]
    return StockLevel.query.filter(StockLevel.place_id.in_(ids),
                                   StockLevel.quantity > 0).first() is not None
