"""Keep a machine's status in step with its work orders (feature step 2).

Owner's decisions (2026-10-25): whoever raises an order for a machine must say whether the
fault takes it out of play, because a screen that burns out and a button that sticks are not
the same; and closing the order puts the machine back to working.

The status follows the machine's open "down" orders:

* one or more open, none in progress  -> Not_Working
* one or more open, any in progress   -> Being_Fixed
* none open any more                  -> Working, if an order's change left it that way --
  unless the last down order was closed as Deferred, which leaves it Not_Working: deferring a
  fault doesn't make the machine work.

Orders that don't say (``machine_down`` is None: older orders, coin-door reports, GATBOX,
general orders) and "still playable" orders never change the status. Neither is a Retired
machine ever touched. A status someone set by hand stays until an order says otherwise.

Each change goes through the history hook like any other, tagged with the order that caused
it, so the machine page can say "work order #12".
"""
from __future__ import annotations

from app.models import Game, MaintenanceRecord

OPEN = ("Open", "In_Progress")
DOWN_STATUSES = ("Not_Working", "Being_Fixed")
CHOICES = {"yes": True, "no": False}


def parse_choice(raw: str | None) -> bool | None:
    """The form's ``machine_down`` value: "yes", "no", or anything else for not chosen."""
    return CHOICES.get((raw or "").strip().lower())


def _before(order: MaintenanceRecord, attr: str):
    """The attribute's value before this unsaved change (its current value if unchanged)."""
    from sqlalchemy import inspect

    hist = inspect(order).attrs[attr].history
    return hist.deleted[0] if hist.deleted else getattr(order, attr)


def sync_machine_status(order: MaintenanceRecord, *, deleting: bool = False) -> None:
    """Set the order's machine to what its open "down" orders say, if this order's change
    matters: it was open and down before, or is now. Call before committing."""
    from app.extensions import db

    # Read the before/after first, and let nothing flush meanwhile: loading order.game runs a
    # query, which would auto-flush the pending change and wipe the history this depends on.
    with db.session.no_autoflush:
        was_open_down = (bool(_before(order, "machine_down"))
                         and _before(order, "status") in OPEN)
        now_open_down = not deleting and bool(order.machine_down) and order.status in OPEN
        if not (was_open_down or now_open_down):
            return        # a playable order, an unstated one, or an old closed one: no say
        _apply(order, deleting)


def _apply(order: MaintenanceRecord, deleting: bool) -> None:
    game: Game | None = order.game
    if game is None or game.status == "Retired":
        return

    orders = list({id(o): o for o in [*game.maintenance_records, order]}.values())
    if deleting:
        orders = [o for o in orders if o is not order]
    open_down = [o for o in orders if o.machine_down and o.status in OPEN]

    if open_down:
        target = ("Being_Fixed" if any(o.status == "In_Progress" for o in open_down)
                  else "Not_Working")
    elif not deleting and order.machine_down and order.status == "Deferred":
        target = "Not_Working"
    elif game.status in DOWN_STATUSES:
        target = "Working"     # the last down order was fixed, deleted, or made playable
    else:
        return
    if game.status != target:
        if not deleting:          # a deleted order can't be linked to from the history
            game._history_order_id = order.id
        game.status = target
