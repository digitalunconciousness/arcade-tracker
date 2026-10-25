"""The rotation planner (feature step 4): which floor games to swap for which warehouse games.

What the tracker was first built for: the arcade has more games than floor space, and the
quiet ones on the floor should go back for ones that did better.

**Plays per working day.** A reading's plays are spread evenly over the days it covers on
which the machine was on the floor and working (from the location and status history), and
the rate is plays over those days. A game broken for half the month doesn't look unpopular,
and days with no reading yet aren't counted as zero.

Before history started (migration d1e2f3a4b5c6) a machine is taken to have been where its
baseline row says. A warehouse game whose last time on the floor predates history is judged
on its old readings instead, which the page says.

Operators choose the window, whether swaps pair like with like, and how long a game settles
on the floor before it can be judged (owner's decision, 2026-10-25: other arcades will want
other settings). The defaults are here, in one place.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from itertools import pairwise

from app.models import Game, GameEvent, PlayRecord
from app.services.collection import local_today
from app.utils.helpers import looks_like_pinball

WINDOWS = (30, 60, 90, 180, 365)
SETTLE_DAYS = (0, 30, 60, 90)
PAIRINGS = {"kind": "Same type", "any": "Any type"}  # pinball or video
DEFAULTS = {"window": 90, "pairing": "kind", "settle": 30}

MIN_DAYS = 7          # fewer counted days than this and the rate isn't shown
BETTER_BY = 1.2       # a swap is suggested only for a game doing 20% better
FADE_SPAN = 30        # first month on the floor against the latest month


@dataclass
class Options:
    window: int = DEFAULTS["window"]
    pairing: str = DEFAULTS["pairing"]
    settle: int = DEFAULTS["settle"]

    @classmethod
    def from_args(cls, args) -> Options:
        def pick(name, allowed, cast=int):
            try:
                value = cast(args.get(name, DEFAULTS[name]))
            except (TypeError, ValueError):
                return DEFAULTS[name]
            return value if value in allowed else DEFAULTS[name]

        return cls(pick("window", WINDOWS), pick("pairing", PAIRINGS, str),
                   pick("settle", SETTLE_DAYS))

    def args(self) -> dict:
        return {"window": self.window, "pairing": self.pairing, "settle": self.settle}


@dataclass
class Rate:
    plays: float
    days: int
    value: float              # token value of those plays

    @property
    def per_day(self) -> float | None:
        return self.plays / self.days if self.days >= MIN_DAYS else None

    @property
    def value_per_day(self) -> float | None:
        return self.value / self.days if self.days >= MIN_DAYS else None


@dataclass
class Machine:
    game: Game
    pinball: bool
    rate: Rate | None = None            # floor: over the window; warehouse: its last stint
    floor_since: dt.date | None = None  # None: since before history started
    down_days: int = 0                  # on the floor but not working, within the window
    fade: float | None = None           # latest month against first month, as a fraction
    stint: tuple[dt.date, dt.date] | None = None
    from_readings: bool = False         # warehouse: judged on old readings, not history
    settling_left: int = 0

    @property
    def kind(self) -> str:
        return "Pinball" if self.pinball else "Video"


@dataclass
class Swap:
    out: Machine
    into: Machine

    @property
    def gain(self) -> float:
        return self.into.rate.per_day - self.out.rate.per_day


# --- the day-by-day picture of one machine ------------------------------------------------------

class Timeline:
    """Where a machine was, and whether it worked, on each day; and its plays spread over days."""

    def __init__(self, game: Game, events: list[GameEvent], records: list[PlayRecord]):
        self.game = game
        self.events = sorted(events, key=lambda e: (e.occurred_at, e.id or 0))
        self.records = sorted(records, key=lambda r: (r.date_recorded, r.id or 0))
        self._start = {k: next((e.new_value for e in self.events if e.kind == k),
                               getattr(game, k)) for k in ("location", "status")}

    def states(self, first: dt.date, last: dt.date) -> dict[dt.date, tuple[str, str]]:
        out, now, i = {}, dict(self._start), 0
        day = first
        while day <= last:
            while i < len(self.events) and self.events[i].occurred_at.date() <= day:
                now[self.events[i].kind] = self.events[i].new_value
                i += 1
            out[day] = (now["location"], now["status"])
            day += dt.timedelta(days=1)
        return out

    def rate(self, first: dt.date, last: dt.date, *, from_readings: bool = False) -> Rate:
        """Plays per available day between *first* and *last*, inclusive.

        Available means on the floor and working. With *from_readings* the history is not
        consulted: every reading that saw plays counts all of its days, which is the best
        that can be said of a game whose time on the floor predates the history.
        """
        if len(self.records) < 2:
            return Rate(0, 0, 0)
        states = self.states(min(first, self.records[0].date_recorded),
                             max(last, self.records[-1].date_recorded))
        price = self.game.coins_per_play or 0
        plays = value = 0.0
        days: set[dt.date] = set()
        for prev, cur in pairwise(self.records):
            covered = [prev.date_recorded + dt.timedelta(days=n + 1)
                       for n in range((cur.date_recorded - prev.date_recorded).days)]
            if not covered:
                continue
            if from_readings:
                if cur.plays_count <= 0:
                    continue
                open_days = covered
            else:
                # Plays taken while the history says it was away or down mean the history is
                # wrong for those days, so they count as available rather than inflating the rate.
                open_days = [d for d in covered if states[d] == ("Floor", "Working")] or covered
            share = cur.plays_count / len(open_days)
            for d in open_days:
                if first <= d <= last:
                    plays += share
                    value += share * price
                    days.add(d)
        return Rate(plays, len(days), value)

    def floor_since(self) -> dt.date | None:
        """The day the current stint on the floor began, or None if before history."""
        moves = [e for e in self.events if e.kind == "location" and e.source != "baseline"]
        last_in = next((e for e in reversed(moves) if e.new_value == "Floor"), None)
        return last_in.occurred_at.date() if last_in else None

    def last_stint(self) -> tuple[dt.date, dt.date] | None:
        """The most recent time on the floor that has ended, from the history."""
        start = None
        stint = None
        loc = self._start["location"]
        known = False
        for e in self.events:
            if e.kind != "location":
                continue
            if e.source == "baseline":
                loc = e.new_value
                continue
            day = e.occurred_at.date()
            if e.new_value == "Floor" and loc != "Floor":
                start, known = day, True
            elif e.new_value != "Floor" and loc == "Floor" and known:
                stint = (start, day - dt.timedelta(days=1))
            loc = e.new_value
        return stint


# --- the plan -----------------------------------------------------------------------------------

def _by_game(model, ids):
    out = {i: [] for i in ids}
    if ids:
        for row in model.query.filter(model.game_id.in_(ids)).all():
            out[row.game_id].append(row)
    return out


@dataclass
class Plan:
    options: Options
    floor: list[Machine]
    warehouse: list[Machine]
    swaps: list[Swap]
    untried: list[Machine]


def plan(options: Options | None = None, today: dt.date | None = None) -> Plan:
    options = options or Options()
    today = today or local_today()
    first = today - dt.timedelta(days=options.window - 1)
    games = Game.query.filter(Game.status != "Retired").all()
    ids = [g.id for g in games]
    events, records = _by_game(GameEvent, ids), _by_game(PlayRecord, ids)

    floor, warehouse = [], []
    for g in games:
        t = Timeline(g, events[g.id], records[g.id])
        m = Machine(g, looks_like_pinball(g.genre, g.name))
        if g.location == "Floor":
            m.rate = t.rate(first, today)
            m.floor_since = t.floor_since()
            states = t.states(first, today)
            m.down_days = sum(1 for loc, st in states.values()
                              if loc == "Floor" and st in ("Not_Working", "Being_Fixed"))
            if m.floor_since:
                on_floor = (today - m.floor_since).days
                m.settling_left = max(0, options.settle - on_floor)
                if on_floor >= 2 * FADE_SPAN:
                    early = t.rate(m.floor_since, m.floor_since + dt.timedelta(FADE_SPAN - 1))
                    late = t.rate(today - dt.timedelta(FADE_SPAN - 1), today)
                    if early.per_day and late.per_day is not None:
                        m.fade = late.per_day / early.per_day - 1
            floor.append(m)
        else:
            stint = t.last_stint()
            if stint:
                m.stint = stint
                m.rate = t.rate(*stint)
            elif t.records:
                m.rate = t.rate(t.records[0].date_recorded, today, from_readings=True)
                m.from_readings = True
                if not m.rate.plays:
                    m.rate = None          # never took a token that anyone wrote down
            warehouse.append(m)

    def per_day(m):
        return m.rate.per_day if m.rate else None

    floor.sort(key=lambda m: (per_day(m) is None, per_day(m) or 0))       # quietest first
    warehouse.sort(key=lambda m: (per_day(m) is None, -(per_day(m) or 0)))  # best first
    untried = [m for m in warehouse if not m.rate or m.rate.per_day is None]
    return Plan(options, floor, warehouse, _pair(floor, warehouse, options), untried)


def _pair(floor: list[Machine], warehouse: list[Machine], options: Options) -> list[Swap]:
    outs = [m for m in floor if m.rate and m.rate.per_day is not None and not m.settling_left]
    ins = [m for m in warehouse if m.rate and m.rate.per_day is not None
           and m.game.status == "Working"]
    swaps, used = [], set()
    for out in outs:                                  # quietest first
        for into in ins:                              # best first
            if into.game.id in used:
                continue
            if options.pairing == "kind" and into.pinball != out.pinball:
                continue
            if into.rate.per_day > out.rate.per_day * BETTER_BY:
                swaps.append(Swap(out, into))
                used.add(into.game.id)
                break
    return swaps


def swap(out: Game, into: Game) -> None:
    """Send *out* to the warehouse and bring *into* onto the floor, in its place.

    The incoming game takes the outgoing one's floor position, and the outgoing one takes the
    warehouse section the incoming one left. The history hook records both moves. Caller
    commits.
    """
    out.location, into.location = "Warehouse", "Floor"
    into.floor_position, out.floor_position = out.floor_position, None
    out.warehouse_section, into.warehouse_section = into.warehouse_section, None
