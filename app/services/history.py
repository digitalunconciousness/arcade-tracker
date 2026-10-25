"""Record every location and status change as a GameEvent, and read them back.

The ``before_flush`` hook sees every Game about to be written, whichever page, script or bulk
action changed it, and adds an event for each changed field. It only ever adds rows: what is
being saved is never touched.
"""
from __future__ import annotations

from sqlalchemy import event, inspect
from sqlalchemy.orm import Session

from app.models import Game
from app.models.history import KINDS, GameEvent, _utc_now


def _actor_id() -> int | None:
    """The signed-in user, if this flush happens during a request by one."""
    from flask import has_request_context
    from flask_login import current_user

    if has_request_context() and current_user and current_user.is_authenticated:
        return current_user.id
    return None


def _record(session: Session, flush_context, instances) -> None:
    now = _utc_now()
    events = []
    for obj in session.new:
        if isinstance(obj, Game):
            for kind in KINDS:
                value = getattr(obj, kind) or Game.__table__.c[kind].default.arg
                events.append({"game": obj, "kind": kind, "old_value": None,
                               "new_value": value, "source": "created"})
    for obj in session.dirty:
        if not isinstance(obj, Game) or obj in session.deleted:
            continue
        state = inspect(obj)
        for kind in KINDS:
            hist = state.attrs[kind].history
            if not hist.has_changes():
                continue
            old = hist.deleted[0] if hist.deleted else None
            new = hist.added[0] if hist.added else None
            if new is None or old == new:
                continue
            events.append({"game": obj, "kind": kind, "old_value": old, "new_value": new,
                           "source": "change",
                           # set by app/services/downtime.py when a work order made the change
                           "maintenance_id": getattr(obj, "_history_order_id", None)
                           if kind == "status" else None})
        if hasattr(obj, "_history_order_id"):
            del obj._history_order_id
    if not events:
        return
    actor = _actor_id()
    for e in events:
        # Through the relationship, so a machine being created (no id yet) links up too.
        session.add(GameEvent(occurred_at=now, user_id=actor, **e))


def install() -> None:
    """Listen on every session. Idempotent: create_app() may run more than once per process."""
    if not event.contains(Session, "before_flush", _record):
        event.listen(Session, "before_flush", _record)


def timeline(game_id: int, limit: int | None = None) -> list[GameEvent]:
    """A machine's events, newest first."""
    q = (GameEvent.query.filter_by(game_id=game_id)
         .order_by(GameEvent.occurred_at.desc(), GameEvent.id.desc()))
    return q.limit(limit).all() if limit else q.all()
