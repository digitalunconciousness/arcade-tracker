"""The collection round: walk the floor, read every coin meter, and catch odd numbers on the spot.

Owner's decisions (2026-10-25):

* A round is one day. A machine read today is done, however it was read, so there is nothing
  to start or close and no table to keep: the round is today's readings.
* While someone has a round open, scanning a machine's label opens its meter entry instead of
  its page (``/g/<code>`` itself never changes).
* Three things are flagged as you go: no plays since the last reading, far more plays than the
  machine usually does, and a long gap since the last reading. A backwards reading is refused,
  as it always was. "Far more" is held back until it is confirmed, because a typo there would
  inflate the totals and make the next honest reading look like the meter went backwards.

Plays come first everywhere here; the token value is shown second (owner's wording rule).
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from itertools import pairwise

from app.models import Game, PlayRecord

LONG_GAP_DAYS = 30
# "Far more than usual": over HIGH_FACTOR times what the machine's usual daily rate predicts
# for the days since its last reading, and by more than HIGH_MARGIN plays, so a quiet machine
# having one busy week isn't flagged over a handful of plays.
HIGH_FACTOR = 3
HIGH_MARGIN = 50
# The usual rate needs this much history to mean anything; a newer machine is never flagged.
MIN_RATE_DAYS = 7
RATE_READINGS = 6          # the last six intervals: recent enough to follow a fading game


def local_today() -> dt.date:
    """The arcade's day: the server's local date, which is what a meter reading's date has
    always meant (``PlayRecord.date_recorded`` defaults to ``date.today``)."""
    return dt.date.today()  # noqa: DTZ011 -- local on purpose, see above


@dataclass
class Flag:
    kind: str              # "none" | "high" | "gap"
    text: str


@dataclass
class Stop:
    """One machine on the round."""

    game: Game
    records: list[PlayRecord]          # oldest first, today's included
    today: dt.date
    flags: list[Flag] = field(default_factory=list)

    @property
    def meter_ok(self) -> bool:
        return self.game.counter_status == "Working"

    @property
    def read_today(self) -> PlayRecord | None:
        todays = [r for r in self.records if r.date_recorded == self.today]
        return todays[-1] if todays else None

    @property
    def before(self) -> list[PlayRecord]:
        """The readings before today's: what a new reading is compared with."""
        return [r for r in self.records if r.date_recorded < self.today]

    @property
    def last(self) -> PlayRecord | None:
        before = self.before
        return before[-1] if before else None

    @property
    def last_count(self) -> int:
        return self.last.coin_count if self.last else 0

    @property
    def first_reading(self) -> bool:
        return not self.before

    @property
    def done(self) -> bool:
        return self.read_today is not None

    @property
    def to_do(self) -> bool:
        return self.meter_ok and not self.done


def _natural(text: str | None) -> tuple:
    """Sort "A2" before "A10": floor positions are free text, often a row letter and a number."""
    return tuple((0, int(p)) if p.isdigit() else (1, p.lower())
                 for p in re.split(r"(\d+)", text or "") if p)


def round_games() -> list[Game]:
    """Every machine on the floor that isn't retired, in walking order: by floor position,
    machines with no position last, then by name."""
    games = (Game.query.filter(Game.location == "Floor", Game.status != "Retired").all())
    return sorted(games, key=lambda g: (not g.floor_position, _natural(g.floor_position),
                                        g.name.lower()))


def on_round(game: Game) -> bool:
    return game.location == "Floor" and game.status != "Retired"


def _records(game_ids: list[int]) -> dict[int, list[PlayRecord]]:
    out: dict[int, list[PlayRecord]] = {gid: [] for gid in game_ids}
    if not game_ids:
        return out
    rows = (PlayRecord.query.filter(PlayRecord.game_id.in_(game_ids))
            .order_by(PlayRecord.date_recorded, PlayRecord.id).all())
    for r in rows:
        out[r.game_id].append(r)
    return out


def stop_for(game: Game, today: dt.date | None = None) -> Stop:
    today = today or local_today()
    stop = Stop(game, _records([game.id])[game.id], today)
    if stop.read_today:
        stop.flags = assess(stop.before, stop.read_today.plays_count, today)
    return stop


def plan(today: dt.date | None = None) -> list[Stop]:
    """The whole round, in walking order, with today's flags worked out."""
    today = today or local_today()
    games = round_games()
    records = _records([g.id for g in games])
    stops = [Stop(g, records[g.id], today) for g in games]
    for s in stops:
        if s.read_today:
            s.flags = assess(s.before, s.read_today.plays_count, today)
    return stops


def next_stop(stops: list[Stop], after_game_id: int | None = None) -> Stop | None:
    """The next machine still to read after this one, wrapping round to the start."""
    ids = [s.game.id for s in stops]
    start = ids.index(after_game_id) + 1 if after_game_id in ids else 0
    for s in stops[start:] + stops[:start]:
        if s.to_do and s.game.id != after_game_id:
            return s
    return None


def usual_daily_plays(before: list[PlayRecord]) -> float | None:
    """Plays per day over the last few readings, or None when there's too little history."""
    intervals = list(pairwise(before))[-RATE_READINGS:]
    days = sum((b.date_recorded - a.date_recorded).days for a, b in intervals)
    if days < MIN_RATE_DAYS:
        return None
    return sum(b.plays_count for _, b in intervals) / days


def assess(before: list[PlayRecord], plays: int, today: dt.date) -> list[Flag]:
    """What looks odd about *plays* new plays read on *today*, given the readings before."""
    if not before:
        return []                      # a first reading only sets the starting point
    last = before[-1]
    days = (today - last.date_recorded).days
    since = f"{last.date_recorded.day} {last.date_recorded:%b}"
    flags = []
    if plays == 0:
        flags.append(Flag("none", f"No plays since {since}. Is the meter stuck, or the game "
                                  "not taking tokens?"))
    rate = usual_daily_plays(before)
    if rate is not None and days > 0:
        expected = rate * days
        if plays > HIGH_FACTOR * expected and plays - expected > HIGH_MARGIN:
            flags.append(Flag("high", f"{plays:,} plays is far more than usual: about "
                                      f"{round(expected):,} for {days} days. Check the number."))
    if days >= LONG_GAP_DAYS:
        flags.append(Flag("gap", f"Last read {days} days ago ({since}), so these plays are "
                                 "spread over a long time."))
    return flags
