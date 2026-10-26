"""Planned counts (inventory step 5): full and cycle counts, reviewed before they're applied.

A count is a list of (part, place) lines with what was on record when it started. Counters
fill them in blind: the page they use doesn't show the number on record, so they count what
is there rather than confirm what they expect. Parts found where nothing was expected are
added as they're found. Nothing changes until a manager reviews the differences and applies
them; each applied line sets that place to what was counted, through ``stock_places``.
A count can repeat: applying it starts the next one, due *repeat_days* later.

Quick count mode (a place's "Count this place") still saves straight away; this is for the
counts after the first. Callers commit.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from app.extensions import db
from app.models import InventoryItem, StockCount, StockCountLine, StockLevel, StockPlace
from app.services import stock_places
from app.services.collection import local_today


class CountError(ValueError):
    """A change that can't be made; the message is for the person who asked."""


MAX_NAME = 100
MAX_CYCLE = 500


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


def _places_and_below(places: list[StockPlace]) -> list[StockPlace]:
    seen: dict[int, StockPlace] = {}
    for place in places:
        for p in [place, *place.descendants()]:
            if not p.archived:
                seen[p.id] = p
    return list(seen.values())


def _line(count, item, place, expected):
    db.session.add(StockCountLine(count=count, item=item, place=place, expected=expected))


def _clean(name, kind, due, repeat_days):
    name = " ".join((name or "").split()) or ("Cycle count" if kind == "cycle" else "Count")
    if len(name) > MAX_NAME:
        raise CountError(f"Keep the name to {MAX_NAME} characters.")
    if repeat_days is not None and not 1 <= repeat_days <= 366:
        raise CountError("Repeat every 1 to 366 days.")
    return name


def start_full(name: str, places: list[StockPlace], user_id: int,
               due: dt.date | None = None, repeat_days: int | None = None) -> StockCount:
    """Every part on record in *places* and the places inside them."""
    name = _clean(name, "full", due, repeat_days)
    if not places:
        raise CountError("Pick at least one place to count.")
    count = StockCount(name=name, kind="full", due=due, repeat_days=repeat_days,
                       place_ids=",".join(str(p.id) for p in places), created_by_id=user_id)
    db.session.add(count)
    for place in _places_and_below(places):
        for level in StockLevel.query.filter_by(place_id=place.id).all():
            _line(count, level.item, place, level.quantity or 0)
    return count


def pick_cycle(size: int) -> list[InventoryItem]:
    """The *size* parts in stock counted longest ago (never counted first), by the oldest
    count of any of their places."""
    # (counted at all, when): never counted sorts first, then the oldest count.
    oldest: dict[int, tuple[bool, dt.datetime | None]] = {}
    for level in StockLevel.query.all():
        if level.place.archived:
            continue
        key = (level.counted is not None, level.counted)
        prev = oldest.get(level.item_id)
        if prev is None or (key[0], key[1] or 0) < (prev[0], prev[1] or 0):
            oldest[level.item_id] = key
    ids = sorted(oldest, key=lambda i: (oldest[i][0], oldest[i][1] or 0, i))[:size]
    items = {i.id: i for i in InventoryItem.query.filter(InventoryItem.id.in_(ids or [0]))}
    return [items[i] for i in ids if i in items]


def start_cycle(name: str, size: int, user_id: int, due: dt.date | None = None,
                repeat_days: int | None = None) -> StockCount:
    """The *size* parts counted longest ago, in every place each is kept."""
    name = _clean(name, "cycle", due, repeat_days)
    if not 1 <= size <= MAX_CYCLE:
        raise CountError(f"A cycle count is 1 to {MAX_CYCLE} parts.")
    items = pick_cycle(size)
    if not items:
        raise CountError("There are no parts in stock to count yet.")
    count = StockCount(name=name, kind="cycle", due=due, repeat_days=repeat_days,
                       cycle_size=size, created_by_id=user_id)
    db.session.add(count)
    for item in items:
        for level in item.levels:
            if not level.place.archived:
                _line(count, item, level.place, level.quantity or 0)
    return count


def _open(count):
    if count.status != "Counting":
        raise CountError(f"Count #{count.id} is {count.status.lower()}.")


def record(line: StockCountLine, value: int | None, user_id: int) -> None:
    """A counter's number for one line (None clears it)."""
    _open(line.count)
    line.counted = value
    line.counted_by_id = user_id if value is not None else None
    line.counted_at = _now() if value is not None else None


def add_found(count: StockCount, item: InventoryItem, place: StockPlace, value: int,
              user_id: int) -> StockCountLine:
    """A part found in a place the count didn't list."""
    _open(count)
    if place.archived:
        raise CountError(f"{place.path} is archived.")
    existing = next((ln for ln in count.lines
                     if ln.item_id == item.id and ln.place_id == place.id), None)
    if existing is None:
        level = stock_places.level_of(item, place)
        existing = StockCountLine(count=count, item=item, place=place,
                                  expected=level.quantity if level else 0)
        db.session.add(existing)
    record(existing, value, user_id)
    return existing


@dataclass
class Difference:
    line: StockCountLine
    now: int           # on record now (it may have moved since the count started)

    @property
    def change(self) -> int:
        return (self.line.counted or 0) - self.now


def review(count: StockCount) -> tuple[list[Difference], list[Difference], list[StockCountLine]]:
    """(lines that differ, lines that match, lines not counted), against the stock now."""
    differ, match, missing = [], [], []
    for line in count.lines:
        if line.counted is None:
            missing.append(line)
            continue
        level = stock_places.level_of(line.item, line.place)
        diff = Difference(line, level.quantity if level else 0)
        (differ if diff.change else match).append(diff)
    differ.sort(key=lambda d: (-abs(d.change), d.line.item.name.lower()))
    return differ, match, missing


def apply(count: StockCount, user_id: int) -> tuple[int, StockCount | None]:
    """Set every counted line's place to what was counted. Lines not counted are left as
    they are. Returns (lines changed, the next count when it repeats)."""
    _open(count)
    if not count.counted:
        raise CountError("Nothing has been counted yet.")
    changed = 0
    for line in count.lines:
        if line.counted is None:
            continue
        level = stock_places.level_of(line.item, line.place)
        if (level.quantity if level else 0) != line.counted:
            stock_places.count(line.item, line.counted, user_id, line.place, f"Count #{count.id}")
            changed += 1
        elif level is not None:
            level.counted = _now()          # confirmed: no history row for "no change"
    count.status, count.applied, count.applied_by_id = "Applied", _now(), user_id
    return changed, _repeat(count, user_id)


def _repeat(count, user_id):
    if not count.repeat_days:
        return None
    due = local_today() + dt.timedelta(days=count.repeat_days)
    try:
        if count.kind == "cycle":
            return start_cycle(count.name, count.cycle_size or 10, user_id, due,
                               count.repeat_days)
        ids = [int(i) for i in (count.place_ids or "").split(",") if i.isdigit()]
        places = [p for p in StockPlace.query.filter(StockPlace.id.in_(ids or [0]))
                  if not p.archived]
        return start_full(count.name, places, user_id, due, count.repeat_days) if places else None
    except CountError:
        return None


def cancel(count: StockCount) -> None:
    _open(count)
    count.status = "Cancelled"


def overdue(today: dt.date | None = None) -> list[StockCount]:
    today = today or local_today()
    return (StockCount.query.filter(StockCount.status == "Counting",
                                    StockCount.due.isnot(None), StockCount.due < today)
            .order_by(StockCount.due).all())
