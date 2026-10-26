"""Serialized spares (inventory step 4): units of a part tracked one by one.

A unit is in stock (in a place), in a machine, out for repair, or retired. Units in a place
are part of that place's stock level, so every move here also goes through
``stock_places``: putting a unit in a machine takes one from its place; taking it out puts
one back. Out for repair and retired units aren't stock. Every change is a ``UnitEvent``.

A part that already had stock when it became tracked has units without a serial yet; they
are recorded (``record``) without changing the stock. Callers commit.
"""

from __future__ import annotations

from collections import Counter

from app.extensions import db
from app.models import Game, InventoryItem, SerialUnit, StockPlace, UnitEvent
from app.services import stock_places


class SerialError(ValueError):
    """A change that can't be made; the message is for the person who asked."""


MAX_SERIAL = 100
MAX_NOTE = 500


def _event(unit, kind, detail, user_id, note=None, order=None):
    db.session.add(UnitEvent(unit=unit, kind=kind, detail=(detail or "")[:300] or None,
                             note=((note or "").strip()[:MAX_NOTE] or None), user_id=user_id,
                             order=order))


def _usable(place):
    if place is None:
        raise SerialError("Pick a place.")
    if place.archived:
        raise SerialError(f"{place.path} is archived.")
    return place


def parse_serials(text: str | None) -> list[str]:
    """One serial per line (or separated by commas), blanks dropped, repeats refused."""
    serials = [" ".join(s.split()) for s in (text or "").replace(",", "\n").splitlines()]
    serials = [s for s in serials if s]
    if not serials:
        raise SerialError("Type at least one serial number.")
    long = [s for s in serials if len(s) > MAX_SERIAL]
    if long:
        raise SerialError(f"A serial number is at most {MAX_SERIAL} characters.")
    twice = [s for s, n in Counter(s.lower() for s in serials).items() if n > 1]
    if twice:
        raise SerialError(f"{twice[0]} is listed twice.")
    return serials


def find_unit(item: InventoryItem, serial: str) -> SerialUnit | None:
    return next((u for u in item.units if u.serial.lower() == serial.lower()), None)


def in_place(item: InventoryItem, place: StockPlace) -> int:
    return sum(1 for u in item.units if u.state == "in_stock" and u.place_id == place.id)


def unrecorded(item: InventoryItem) -> list[tuple[StockPlace, int]]:
    """Places holding more of the part than it has units recorded there: stock from before
    the part was tracked, or changed by the plain stock form."""
    out = []
    for level in item.levels:
        gap = (level.quantity or 0) - in_place(item, level.place)
        if gap > 0:
            out.append((level.place, gap))
    return sorted(out, key=lambda pg: pg[0].path)


def mismatched(item: InventoryItem) -> list[tuple[StockPlace, int, int]]:
    """Places with more units recorded than the stock level says: (place, units, level)."""
    levels = {lv.place_id: lv.quantity or 0 for lv in item.levels}
    places = {u.place_id: u.place for u in item.units if u.state == "in_stock" and u.place}
    out = []
    for pid, place in places.items():
        units = in_place(item, place)
        if units > levels.get(pid, 0):
            out.append((place, units, levels.get(pid, 0)))
    return out


def add_units(item: InventoryItem, serials_text: str, place: StockPlace, user_id: int,
              arriving: bool, note: str = "") -> list[SerialUnit]:
    """New units into *place*. *arriving*: they are new stock (the level goes up).
    Otherwise they are already on the shelf, just never recorded (the level stays)."""
    if not item.serialized:
        raise SerialError(f"{item.name} isn't tracked one by one. Turn that on first.")
    place = _usable(place)
    serials = parse_serials(serials_text)
    taken = [s for s in serials if find_unit(item, s)]
    if taken:
        raise SerialError(f"{item.name} already has a unit {taken[0]}.")
    if not arriving:
        level = stock_places.level_of(item, place)
        free = (level.quantity if level else 0) - in_place(item, place)
        if len(serials) > free:
            raise SerialError(f"{place.path} has {max(free, 0)} without a serial recorded. "
                              "To add new stock, choose “They just arrived”.")
    else:
        stock_places.add(item, len(serials), user_id, place,
                         f"{len(serials)} added with serial numbers")
    units = []
    for serial in serials:
        unit = SerialUnit(item=item, serial=serial, state="in_stock", place=place)
        db.session.add(unit)
        _event(unit, "added" if arriving else "recorded", place.path, user_id, note)
        units.append(unit)
    return units


def move(unit: SerialUnit, dest: StockPlace, user_id: int, note: str = "") -> None:
    if unit.state != "in_stock":
        raise SerialError("Only a unit on a shelf can be moved to another place.")
    dest = _usable(dest)
    if dest.id == unit.place_id:
        raise SerialError("It's already there.")
    source = unit.place
    stock_places.move(unit.item, 1, user_id, source, dest, f"Unit {unit.serial}")
    unit.place = dest
    _event(unit, "moved", f"{source.path} → {dest.path}", user_id, note)


def install(unit: SerialUnit, game: Game, user_id: int, note: str = "", order=None) -> None:
    """From a shelf into a machine: one fewer in that place."""
    if unit.state != "in_stock":
        raise SerialError("Put it back in stock first: only a unit on a shelf can be "
                          "installed.")
    if game is None:
        raise SerialError("Pick the machine.")
    source = unit.place
    stock_places.take(unit.item, 1, user_id, source,
                      f"Unit {unit.serial} installed in {game.name}", kind="used")
    unit.state, unit.place, unit.game = "in_machine", None, game
    _event(unit, "installed", f"{source.path} → {game.name}", user_id, note, order)


def remove(unit: SerialUnit, dest: StockPlace, user_id: int, note: str = "",
           order=None) -> None:
    """Out of a machine and onto a shelf: one more in that place."""
    if unit.state != "in_machine":
        raise SerialError("It isn't in a machine.")
    dest = _usable(dest)
    game = unit.game
    stock_places.add(unit.item, 1, user_id, dest,
                     f"Unit {unit.serial} taken out of {game.name if game else 'a machine'}",
                     kind="added")
    unit.state, unit.game, unit.place = "in_stock", None, dest
    _event(unit, "removed", f"{game.name if game else 'A machine'} → {dest.path}", user_id,
           note, order)


def send_for_repair(unit: SerialUnit, repair_with: str, user_id: int, note: str = "") -> None:
    """Out to be repaired, from a shelf or straight from a machine. Not stock while away."""
    if unit.state not in ("in_stock", "in_machine"):
        raise SerialError("It's already out for repair, or retired.")
    repair_with = " ".join((repair_with or "").split())[:200] or None
    if unit.state == "in_stock":
        frm = unit.place.path
        stock_places.take(unit.item, 1, user_id, unit.place,
                          f"Unit {unit.serial} sent for repair", kind="removed")
    else:
        frm = unit.game.name if unit.game else "A machine"
    unit.state, unit.place, unit.game, unit.repair_with = "at_repair", None, None, repair_with
    _event(unit, "repair", f"{frm} → {repair_with or 'repair'}", user_id, note)


def back_from_repair(unit: SerialUnit, dest: StockPlace, user_id: int, note: str = "") -> None:
    if unit.state != "at_repair":
        raise SerialError("It isn't out for repair.")
    dest = _usable(dest)
    stock_places.add(unit.item, 1, user_id, dest, f"Unit {unit.serial} back from repair",
                     kind="added")
    who = unit.repair_with
    unit.state, unit.place, unit.repair_with = "in_stock", dest, None
    _event(unit, "returned", f"{who or 'Repair'} → {dest.path}", user_id, note)


def retire(unit: SerialUnit, user_id: int, note: str = "") -> None:
    """Scrapped, sold or lost. Kept, with its history."""
    if unit.state == "retired":
        raise SerialError("It's already retired.")
    frm = unit.where
    if unit.state == "in_stock":
        stock_places.take(unit.item, 1, user_id, unit.place, f"Unit {unit.serial} retired",
                          kind="damaged")
    unit.state, unit.place, unit.game, unit.repair_with = "retired", None, None, None
    _event(unit, "retired", frm, user_id, note)


def set_serialized(item: InventoryItem, on: bool) -> None:
    if not on and any(u.state != "retired" for u in item.units):
        raise SerialError(f"{item.name} has units in service; retire them before it stops "
                          "being tracked one by one.")
    item.serialized = on
