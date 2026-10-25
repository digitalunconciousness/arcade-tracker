"""Preventive maintenance by plays or days (feature step 5).

Owner's decisions (2026-10-25):

* A task comes due after N plays or N days, whichever comes first (a task may set only one).
* When it comes due, a playable work order is raised automatically, once. Due by plays is
  checked when a meter is read; due by days when anyone opens the work orders or the task
  page, because nothing else runs on a timer here.
* A task applies to every machine, to all pinball or all video, or to one machine. Only
  machines on the floor are checked: a game in the warehouse takes no plays and isn't served.
* Closing the order as Fixed starts the count again. Closing it as Deferred doesn't; the task
  is raised again 7 days later if it is still due.
* Managers set the tasks up.

The count starts at the last Fixed order for the task on that machine, or when the task was
set up if it has never been done there.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import Game, MaintenanceRecord, MaintenanceTask, PlayRecord
from app.services.collection import local_today
from app.utils.helpers import looks_like_pinball

DEFER_DAYS = 7
OPEN = ("Open", "In_Progress")


@dataclass
class Standing:
    """Where one task stands on one machine."""

    task: MaintenanceTask
    game: Game
    since: dt.datetime                 # last done, or when the task was set up
    done_before: bool
    plays: int
    days: int
    open_order: MaintenanceRecord | None
    deferred_until: dt.date | None

    @property
    def due(self) -> bool:
        return bool((self.task.every_plays and self.plays >= self.task.every_plays)
                    or (self.task.every_days and self.days >= self.task.every_days))

    @property
    def share(self) -> float:
        """How far along it is, 0 to 1 and over: the nearer of the two limits."""
        shares = []
        if self.task.every_plays:
            shares.append(self.plays / self.task.every_plays)
        if self.task.every_days:
            shares.append(self.days / self.task.every_days)
        return max(shares) if shares else 0.0

    @property
    def state(self) -> str:
        if self.open_order:
            return "open"
        if self.due:
            return "deferred" if self.deferred_until else "due"
        return "ok"

    def reason(self) -> str:
        since = f"{self.since:%d %b %Y}"
        start = "since it was last done" if self.done_before else "since the task was set up"
        parts = []
        if self.task.every_plays:
            parts.append(f"{self.plays:,} of {self.task.every_plays:,} plays")
        if self.task.every_days:
            parts.append(f"{self.days:,} of {self.task.every_days:,} days")
        return f"{' and '.join(parts)} {start} ({since})"


def _after(read_on: dt.date, start: dt.date, *, done_before: bool) -> bool:
    """Whether a reading counts toward the next service. Readings carry a day, not a time: on
    the day of a fix the reading was most likely taken before it, so it doesn't count; on the
    day a task is set up, it does."""
    return read_on > start if done_before else read_on >= start


def applies(task: MaintenanceTask, game: Game) -> bool:
    if game.location != "Floor" or game.status == "Retired":
        return False
    if task.applies_to == "machine":
        return task.game_id == game.id
    if task.applies_to in ("pinball", "video"):
        return looks_like_pinball(game.genre, game.name) == (task.applies_to == "pinball")
    return task.applies_to == "all"


def standings(tasks: list[MaintenanceTask] | None = None, games: list[Game] | None = None,
              today: dt.date | None = None) -> list[Standing]:
    """Every (task, machine) pair that applies, with how far along it is."""
    today = today or local_today()
    tasks = tasks if tasks is not None else MaintenanceTask.query.filter_by(active=True).all()
    games = games if games is not None else Game.query.filter_by(location="Floor").all()
    pairs = [(t, g) for t in tasks for g in games if applies(t, g)]
    if not pairs:
        return []
    game_ids = {g.id for _, g in pairs}
    task_ids = {t.id for t, _ in pairs}
    orders: dict[tuple[int, int], list[MaintenanceRecord]] = {}
    for o in (MaintenanceRecord.query.filter(MaintenanceRecord.pm_task_id.in_(task_ids),
                                             MaintenanceRecord.game_id.in_(game_ids))
              .order_by(MaintenanceRecord.date_reported).all()):
        orders.setdefault((o.pm_task_id, o.game_id), []).append(o)
    earliest = min(t.created_at for t in tasks if t.id in task_ids).date()
    records: dict[int, list[PlayRecord]] = {}
    for r in PlayRecord.query.filter(PlayRecord.game_id.in_(game_ids),
                                     PlayRecord.date_recorded >= earliest).all():
        records.setdefault(r.game_id, []).append(r)

    out = []
    for task, game in pairs:
        mine = orders.get((task.id, game.id), [])
        fixed = [o for o in mine if o.status == "Fixed" and o.date_fixed]
        since = max([o.date_fixed.replace(tzinfo=None) for o in fixed],
                    default=task.created_at.replace(tzinfo=None))
        deferred = [o.date_fixed for o in mine if o.status == "Deferred" and o.date_fixed
                    and o.date_fixed.replace(tzinfo=None) > since]
        until = (max(deferred).date() + dt.timedelta(days=DEFER_DAYS)) if deferred else None
        out.append(Standing(
            task=task, game=game, since=since, done_before=bool(fixed),
            plays=sum(r.plays_count for r in records.get(game.id, [])
                      if _after(r.date_recorded, since.date(), done_before=bool(fixed))),
            days=(today - since.date()).days,
            open_order=next((o for o in reversed(mine) if o.status in OPEN), None),
            deferred_until=until if until and until > today else None,
        ))
    return out


def raise_due(games: list[Game] | None = None, today: dt.date | None = None
              ) -> list[MaintenanceRecord]:
    """Raise an order for each task that is due on a machine and has none open. Commits.

    Safe to run from two requests at once: each order carries a key unique to its task,
    machine and how many orders that pair has had, so the second insert of the same order
    fails on the unique ``external_id`` and is skipped.
    """
    raised = []
    for s in standings(games=games, today=today):
        if s.state != "due":
            continue
        count = MaintenanceRecord.query.filter_by(pm_task_id=s.task.id,
                                                  game_id=s.game.id).count()
        instructions = f"\n\n{s.task.instructions.strip()}" if s.task.instructions else ""
        order = MaintenanceRecord(
            game_id=s.game.id, work_order_type="game", status="Open", priority="Medium",
            issue_description=f"Preventive maintenance: {s.task.name}. Due: {s.reason()}."
                              f"{instructions}",
            machine_down=False, source="pm", pm_task_id=s.task.id,
            external_id=f"pm-{s.task.id}-{s.game.id}-{count + 1}",
        )
        try:
            with db.session.begin_nested():
                db.session.add(order)
            raised.append(order)
        except IntegrityError:
            continue                     # another request raised it first
    db.session.commit()       # also when nothing was raised: don't leave the read open
    return raised
