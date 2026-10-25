"""The rotation planner (feature step 4): rank the floor by plays per working day, show how
warehouse games did when they were out, and suggest swaps.

Owner's decisions (2026-10-25): the window, like-for-like pairing and settle time are the
operator's choice; managers get a button that makes the swap.
"""
from __future__ import annotations

import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import flashes, login
from seed import seed_floor

from app.services.collection import local_today

TODAY = local_today()


def ago(days):
    return TODAY - dt.timedelta(days=days)


def machine(name, location="Floor", status="Working", *, genre=None, price=0.25,
            moves=(), readings=(), position=None):
    """A machine with a written history.

    *moves* are (days_ago, kind, value): the first of each kind is the baseline, the value it
    had when history started; the rest are changes. *readings* are (days_ago, meter).
    """
    from app.extensions import db
    from app.models import Game, GameEvent, PlayRecord

    game = Game(name=name, location=location, status=status, genre=genre,
                coins_per_play=price, counter_status="Working", floor_position=position)
    db.session.add(game)
    db.session.commit()
    GameEvent.query.filter_by(game_id=game.id).delete()
    seen = set()
    for days, kind, value in moves:
        db.session.add(GameEvent(game_id=game.id, kind=kind, new_value=value,
                                 occurred_at=dt.datetime.combine(ago(days), dt.time(12)),
                                 source="change" if kind in seen else "baseline"))
        seen.add(kind)
    last = None
    for days, meter in readings:
        plays = 0 if last is None else meter - last
        db.session.add(PlayRecord(game_id=game.id, coin_count=meter, plays_count=plays,
                                  revenue=plays * price, date_recorded=ago(days)))
        last = meter
    db.session.commit()
    return game.id


def on_floor_all_along():
    return [(400, "location", "Floor"), (400, "status", "Working")]


def find(plan, game_id):
    return next(m for m in plan.floor + plan.warehouse if m.game.id == game_id)


def plan(**options):
    from app.services import rotation

    return rotation.plan(rotation.Options(**options))


# --- plays per working day ----------------------------------------------------------------------

def test_plays_per_working_day(app):
    gid = machine("Comet Chaser", moves=on_floor_all_along(), readings=[(28, 0), (0, 280)])
    rate = find(plan(), gid).rate
    assert (rate.days, round(rate.per_day, 2), round(rate.value_per_day, 2)) == (28, 10.0, 2.5)


def test_days_down_are_not_counted(app):
    """Broken for 14 of 28 days: 280 plays in 14 working days is 20 a day, not 10."""
    gid = machine("Comet Chaser", moves=[*on_floor_all_along(), (20, "status", "Not_Working"),
                                         (6, "status", "Working")],
                  readings=[(28, 0), (0, 280)])
    m = find(plan(), gid)
    assert (m.rate.days, round(m.rate.per_day, 1), m.down_days) == (14, 20.0, 14)


def test_days_not_yet_read_are_not_counted(app):
    gid = machine("Comet Chaser", moves=on_floor_all_along(), readings=[(60, 0), (30, 300)])
    rate = find(plan(window=90), gid).rate
    assert (rate.days, rate.per_day) == (30, 10.0)


def test_the_window_is_the_operators_choice(app):
    gid = machine("Comet Chaser", moves=on_floor_all_along(),
                  readings=[(80, 0), (40, 1200), (0, 1400)])
    assert round(find(plan(window=90), gid).rate.per_day, 2) == 17.5
    assert round(find(plan(window=30), gid).rate.per_day, 2) == 5.0


def test_too_little_data_is_not_ranked(app):
    gid = machine("Comet Chaser", moves=on_floor_all_along(), readings=[(3, 0), (0, 30)])
    assert find(plan(), gid).rate.per_day is None


def test_the_floor_is_ranked_quietest_first(app):
    busy = machine("Busy", moves=on_floor_all_along(), readings=[(28, 0), (0, 560)])
    quiet = machine("Quiet", moves=on_floor_all_along(), readings=[(28, 0), (0, 56)])
    unread = machine("Unread", moves=on_floor_all_along())
    assert [m.game.id for m in plan().floor] == [quiet, busy, unread]


def test_a_fade_since_it_went_out(app):
    """Out 90 days: 600 plays its first month, 150 its latest: down 75%."""
    gid = machine("Comet Chaser", moves=[(400, "location", "Warehouse"),
                                         (400, "status", "Working"), (90, "location", "Floor")],
                  readings=[(90, 0), (60, 600), (30, 900), (0, 1050)])
    m = find(plan(), gid)
    assert m.floor_since == ago(90)
    assert round(m.fade, 2) == -0.75


# --- the warehouse ------------------------------------------------------------------------------

def test_a_warehouse_game_is_judged_on_its_last_time_out(app):
    gid = machine("Orbit Dash", "Warehouse",
                  moves=[(400, "location", "Warehouse"), (400, "status", "Working"),
                         (200, "location", "Floor"), (100, "location", "Warehouse")],
                  readings=[(200, 0), (100, 1000)])
    m = find(plan(), gid)
    assert m.stint == (ago(200), ago(101))
    # Its first day out is the day of the first reading, which no reading covers yet.
    assert m.rate.days == 99 and round(m.rate.per_day, 1) == 10.1 and not m.from_readings


def test_before_history_it_is_judged_on_old_readings(app):
    """Only the readings that saw plays say how it did when it was out."""
    gid = machine("Orbit Dash", "Warehouse",
                  moves=[(100, "location", "Warehouse"), (100, "status", "Working")],
                  readings=[(300, 0), (270, 240), (100, 240)])
    m = find(plan(), gid)
    assert m.from_readings and (m.rate.days, m.rate.per_day) == (30, 8.0)


def test_a_game_never_out_is_untried(app):
    gid = machine("Orbit Dash", "Warehouse",
                  moves=[(100, "location", "Warehouse"), (100, "status", "Working")])
    p = plan()
    assert find(p, gid).rate is None and gid in [m.game.id for m in p.untried]


# --- suggestions --------------------------------------------------------------------------------

def _floor_and_warehouse(genre_in=None, *, out_rate=2, in_rate=8, in_status="Working",
                         placed=400):
    out = machine("Quiet", moves=[(400, "location", "Warehouse"), (400, "status", "Working"),
                                  (placed, "location", "Floor")],
                  readings=[(min(placed, 28), 0), (0, out_rate * min(placed, 28))])
    into = machine("Orbit Dash", "Warehouse", in_status, genre=genre_in,
                   moves=[(400, "location", "Warehouse"), (400, "status", "Working"),
                          (200, "location", "Floor"), (100, "location", "Warehouse")]
                   + ([(50, "status", in_status)] if in_status != "Working" else []),
                   readings=[(200, 0), (100, in_rate * 100)])
    return out, into


def test_a_better_warehouse_game_is_suggested(app):
    out, into = _floor_and_warehouse()
    (swap,) = plan().swaps
    assert (swap.out.game.id, swap.into.game.id) == (out, into)


def test_only_a_clearly_better_game_is_suggested(app):
    _floor_and_warehouse(out_rate=10, in_rate=11)
    assert plan().swaps == []


def test_a_broken_warehouse_game_is_not_suggested(app):
    _floor_and_warehouse(in_status="Not_Working")
    assert plan().swaps == []


def test_like_for_like_is_the_operators_choice(app):
    _floor_and_warehouse("Pinball")
    assert plan(pairing="kind").swaps == []
    assert len(plan(pairing="any").swaps) == 1


def test_a_new_game_settles_first(app):
    _floor_and_warehouse(placed=10)
    p = plan(settle=30)
    assert p.swaps == [] and p.floor[0].settling_left == 20
    assert len(plan(settle=0).swaps) == 1


def test_options_out_of_range_fall_back_to_the_defaults():
    from app.services.rotation import DEFAULTS, Options

    o = Options.from_args({"window": "7", "pairing": "nonsense", "settle": "x"})
    assert o.args() == DEFAULTS
    assert Options.from_args({"window": "365", "pairing": "any", "settle": "0"}).args() == {
        "window": 365, "pairing": "any", "settle": 0}


# --- the page and the swap button ---------------------------------------------------------------

def test_the_page_shows_the_suggestion_and_the_options(client, app):
    seed_floor()
    machine("Quiet", moves=on_floor_all_along(), readings=[(28, 0), (0, 56)])
    machine("Orbit Dash", "Warehouse", moves=[(400, "location", "Warehouse"),
                                              (400, "status", "Working"),
                                              (200, "location", "Floor"),
                                              (100, "location", "Warehouse")],
            readings=[(200, 0), (100, 800)])
    login(client, "manager")
    html = client.get("/rotation/?window=60&pairing=any&settle=0").get_data(as_text=True)
    assert "Quiet → Orbit Dash" in html and "8.1</span> <span class=\"dim\">plays/day" in html
    assert '<option value="60" selected>' in html and '<option value="any" selected>' in html


def test_the_swap_button_moves_both_and_records_who(client, app):
    from app.extensions import db
    from app.models import Game, GameEvent

    seed_floor()
    out = machine("Quiet", moves=on_floor_all_along(), position="B4")
    into = machine("Orbit Dash", "Warehouse", moves=[(400, "location", "Warehouse")])
    db.session.get(Game, into).warehouse_section = "Rack 2"
    db.session.commit()
    login(client, "manager")
    resp = client.post("/rotation/swap", data={"out": out, "into": into, "window": "60"})
    assert resp.headers["Location"].endswith("/rotation/?window=60&pairing=kind&settle=30")
    db.session.expire_all()
    o, i = db.session.get(Game, out), db.session.get(Game, into)
    assert (o.location, o.floor_position, o.warehouse_section) == ("Warehouse", None, "Rack 2")
    assert (i.location, i.floor_position, i.warehouse_section) == ("Floor", "B4", None)
    moved = GameEvent.query.filter_by(game_id=into, kind="location").order_by(
        GameEvent.id.desc()).first()
    assert (moved.new_value, moved.user.username) == ("Floor", "test-manager")
    assert any("Swapped" in m for _, m in flashes(client))


@pytest.mark.parametrize("which", ["both_floor", "retired", "missing"])
def test_a_wrong_swap_moves_nothing(client, app, which):
    from app.extensions import db
    from app.models import Game

    seed_floor()
    out = machine("Quiet", moves=on_floor_all_along())
    into = machine("Orbit Dash", "Floor" if which == "both_floor" else "Warehouse",
                   "Retired" if which == "retired" else "Working")
    login(client, "manager")
    client.post("/rotation/swap", data={"out": out, "into": "x" if which == "missing" else into})
    db.session.expire_all()
    assert db.session.get(Game, out).location == "Floor"
    assert any(c == "error" for c, _ in flashes(client))
