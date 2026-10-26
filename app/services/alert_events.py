"""Which saves raise which alerts (feature step 6).

Hooked on the session, like the history (app/services/history.py), so every page, script and
API call that causes one of these raises its alert, and none can forget to:

* coin_door     a work order filed from a coin-door label
* machine_down  a machine set to Not working, by an order, an edit or a bulk change
* rail_window   a GATBOX session whose verdict is left or over its window
* low_stock     a part dropping to its minimum (a new low-stock alert)
* pm_due        a preventive maintenance order raised
* part_request  a part request marked Shipped or Received

The collection round's flags are raised by the round itself (app/routes/collection.py).

Events are gathered after the flush, when new rows have their ids for the link, and queued
just after it, so the alerts are saved in the same commit as what caused them.
"""
from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

PENDING = "alerts_pending"


def _changed_to(obj, attr: str) -> str | None:
    hist = inspect(obj).attrs[attr].history
    if not hist.added:
        return None
    old = hist.deleted[0] if hist.deleted else None
    return hist.added[0] if hist.added[0] != old else None


def _name(session, model, ident) -> str:
    if ident is None:
        return ""
    with session.no_autoflush:
        row = session.get(model, ident)
    return getattr(row, "name", "") if row is not None else ""


def _gather(session: Session, _ctx) -> None:
    from app.models import (
        Game,
        InventoryItem,
        InventoryRequest,
        LowStockAlert,
        MaintenanceRecord,
        RailSession,
    )

    out = session.info.setdefault(PENDING, [])
    for obj in session.new:
        if isinstance(obj, MaintenanceRecord) and obj.source in ("coindoor", "pm"):
            game = _name(session, Game, obj.game_id) or "A machine"
            if obj.source == "coindoor":
                by = f"From {obj.reported_by}: " if obj.reported_by else ""
                out.append(("coin_door", f"Coin-door report: {game}",
                            f"{by}{obj.issue_description or ''}"[:500],
                            f"/maintenance_detail/{obj.id}"))
            else:
                first = (obj.issue_description or "").split("\n", 1)[0]
                out.append(("pm_due", f"Maintenance due: {game}", first[:500],
                            f"/maintenance_detail/{obj.id}"))
        elif isinstance(obj, RailSession) and obj.verdict in ("left", "over"):
            game = _name(session, Game, obj.game_id) or "the bench"
            out.append(("rail_window", f"Rail {obj.verdict} its window: {game}",
                        f"{obj.rail or 'Rail'} {obj.verdict_detail or ''}".strip()[:500],
                        f"/rails/session/{obj.uid}"))
        elif isinstance(obj, LowStockAlert):
            with session.no_autoflush:
                item = session.get(InventoryItem, obj.item_id)
            if item is not None:
                out.append(("low_stock", f"Low stock: {item.name}",
                            f"{item.stock_quantity} left; the minimum is {item.minimum_stock}.",
                            f"/inventory/{item.id}"))
    for obj in session.dirty:
        if isinstance(obj, Game) and _changed_to(obj, "status") == "Not_Working":
            where = ", ".join(p for p in (obj.location, obj.floor_position) if p)
            out.append(("machine_down", f"Down: {obj.name}",
                        f"Marked not working ({where or 'no location'}).", f"/game/{obj.id}"))
        elif isinstance(obj, InventoryRequest):
            status = _changed_to(obj, "status")
            if status in ("Shipped", "Received"):
                out.append(("part_request", f"Part request {status.lower()}: {obj.item_name}",
                            f"{obj.quantity_requested} requested.",
                            f"/inventory/requests/{obj.id}"))


def _queue(session: Session, _ctx) -> None:
    from app.services.alerts import notify

    pending = session.info.pop(PENDING, [])
    for kind, title, body, path in pending:
        notify(kind, title, body, path)


def install() -> None:
    """Listen on every session. Idempotent, like the history hook."""
    if not event.contains(Session, "after_flush", _gather):
        event.listen(Session, "after_flush", _gather)
    if not event.contains(Session, "after_flush_postexec", _queue):
        event.listen(Session, "after_flush_postexec", _queue)
