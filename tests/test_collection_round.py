"""The collection round (feature step 3): walk the floor and read every coin meter.

Owner's decisions (2026-10-25): a round is one day's readings; while a round is open, scanning a
label opens the meter entry; flag no plays, far more than usual, and a long gap.
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


@pytest.fixture()
def floor(app):
    return seed_floor()


def records(game_id):
    from app.extensions import db
    from app.models import PlayRecord

    db.session.expire_all()
    return (PlayRecord.query.filter_by(game_id=game_id)
            .order_by(PlayRecord.date_recorded, PlayRecord.id).all())


def add_game(name, position=None, location="Floor", **kw):
    from app.extensions import db
    from app.models import Game

    game = Game(name=name, location=location, floor_position=position, status="Working",
                counter_status="Working", coins_per_play=0.25, **kw)
    db.session.add(game)
    db.session.commit()
    return game.id


def read(client, game_id, count, **extra):
    return client.post(f"/round/{game_id}", data={"coin_count": str(count), **extra})


# --- who is on the round, and in what order -----------------------------------------------------

def test_the_round_is_the_floor_in_walking_order(client, floor):
    from app.services.collection import round_games

    a10, a2, nowhere = add_game("Comet Chaser", "A10"), add_game("Orbit Dash", "A2"), \
        add_game("Moon Hopper")
    add_game("Shelf Runner", "B1", location="Warehouse")
    names = [g.name for g in round_games()]
    assert names.index("Orbit Dash") < names.index("Comet Chaser") < names.index("Moon Hopper")
    assert "Pixel Pinball" not in names and "Shelf Runner" not in names
    positioned = [names.index(n) for n in ("Orbit Dash", "Comet Chaser")]
    unpositioned = [names.index(n) for n in ("Moon Hopper", "Neon Raider", "Star Courier")]
    assert max(positioned) < min(unpositioned), "no position walks last"
    assert unpositioned == sorted(unpositioned), "then by name"
    assert {a10, a2, nowhere}


def test_the_overview_shows_each_machine_and_what_is_left(client, floor):
    login(client, "operator")
    html = client.get("/round/").get_data(as_text=True)
    assert "Neon Raider" in html and "Star Courier" in html and "Pixel Pinball" not in html
    assert "0 of 1 read" in html, "a broken meter isn't counted as readable"
    assert "Meter broken" in html and "To read" in html


# --- reading a meter ----------------------------------------------------------------------------

def test_a_reading_records_plays_and_moves_on(client, floor):
    nxt = add_game("Orbit Dash", "A2")
    from app.extensions import db
    from app.models import PlayRecord
    db.session.add(PlayRecord(game_id=nxt, coin_count=10, date_recorded=TODAY - dt.timedelta(7)))
    db.session.commit()

    login(client, "operator")
    resp = read(client, floor["raider"], 160)
    latest = records(floor["raider"])[-1]
    assert (latest.coin_count, latest.plays_count, latest.date_recorded) == (160, 20, TODAY)
    assert latest.revenue == 10.0
    assert resp.headers["Location"].endswith(f"/round/{nxt}")
    assert ("success", "Neon Raider: 20 plays ($10.00).") in flashes(client)


def test_the_last_machine_goes_back_to_the_overview(client, floor):
    login(client, "operator")
    resp = read(client, floor["raider"], 160)
    assert resp.headers["Location"].endswith("/round/")
    assert "Round done" in client.get("/round/").get_data(as_text=True)


def test_a_backwards_reading_is_refused(client, floor):
    login(client, "operator")
    resp = read(client, floor["raider"], 120)
    assert resp.status_code == 400 and "can&#39;t go backwards" in resp.get_data(as_text=True)
    assert len(records(floor["raider"])) == 2


def test_a_first_reading_sets_the_starting_point(client, floor):
    new = add_game("Orbit Dash", "A2")
    login(client, "operator")
    assert "sets the starting point" in client.get(f"/round/{new}").get_data(as_text=True)
    read(client, new, 5000)
    (only,) = records(new)
    assert (only.coin_count, only.plays_count, only.revenue) == (5000, 0, 0.0)


def test_a_machine_is_read_once_a_day(client, floor):
    login(client, "operator")
    read(client, floor["raider"], 160)
    html = read(client, floor["raider"], 170).get_data(as_text=True)
    assert len(records(floor["raider"])) == 3
    assert "was already read today." in html and "Read today" in html


def test_a_broken_meter_cannot_be_read(client, floor):
    login(client, "operator")
    read(client, floor["courier"], 50)
    assert records(floor["courier"]) == []


def test_a_warehouse_machine_is_not_on_the_round(client, floor):
    login(client, "operator")
    resp = client.get(f"/round/{floor['pinball']}")
    assert resp.headers["Location"].endswith(f"/game/{floor['pinball']}")


# --- flags --------------------------------------------------------------------------------------

def test_no_plays_is_saved_and_flagged(client, floor):
    login(client, "operator")
    read(client, floor["raider"], 140)
    assert records(floor["raider"])[-1].plays_count == 0
    assert any(c == "warning" and "No plays since" in m for c, m in flashes(client))
    assert "No plays" in client.get("/round/").get_data(as_text=True)


def test_far_more_than_usual_waits_for_confirmation(client, floor):
    """Neon Raider did 40 plays in 15 days; 5 days on, 200 more is a likely typo."""
    login(client, "operator")
    resp = read(client, floor["raider"], 340)
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200 and "Not saved yet" in html and "far more than usual" in html
    assert len(records(floor["raider"])) == 2
    read(client, floor["raider"], 340, confirm_high="1")
    assert records(floor["raider"])[-1].plays_count == 200
    assert not [m for c, m in flashes(client) if c == "warning"], "confirmed, so not nagged"
    assert "Far above usual" in client.get("/round/").get_data(as_text=True)


def test_a_normal_week_is_not_flagged(client, floor):
    login(client, "operator")
    read(client, floor["raider"], 155)
    assert not [m for c, m in flashes(client) if c == "warning"]


def test_a_long_gap_is_flagged(client, floor):
    from app.extensions import db

    for r in records(floor["raider"]):
        r.date_recorded -= dt.timedelta(days=40)
    db.session.commit()
    login(client, "operator")
    read(client, floor["raider"], 150)
    assert any("Last read 45 days ago" in m for _, m in flashes(client))


def test_a_new_machine_is_never_flagged_high():
    from app.models import PlayRecord
    from app.services.collection import assess

    start = PlayRecord(coin_count=0, plays_count=0, date_recorded=TODAY - dt.timedelta(3))
    assert assess([start], 5000, TODAY) == []


# --- scanning during a round --------------------------------------------------------------------

def test_scanning_opens_the_meter_while_a_round_is_open(client, floor):
    login(client, "operator")
    assert client.get("/g/neon-raider").headers["Location"].endswith(f"/game/{floor['raider']}")
    client.get("/round/")
    assert client.get("/g/neon-raider").headers["Location"].endswith(f"/round/{floor['raider']}")
    assert client.get("/g/pixel-pinball").headers["Location"].endswith(
        f"/game/{floor['pinball']}"), "a warehouse machine still opens its page"
    client.post("/round/end")
    assert client.get("/g/neon-raider").headers["Location"].endswith(f"/game/{floor['raider']}")


def test_yesterdays_round_is_closed(client, floor):
    login(client, "operator")
    with client.session_transaction() as sess:
        sess["collection_round"] = (TODAY - dt.timedelta(1)).isoformat()
    assert client.get("/g/neon-raider").headers["Location"].endswith(f"/game/{floor['raider']}")


def test_the_label_url_itself_is_unchanged(app):
    with app.test_request_context():
        from flask import url_for
        assert url_for("games.resolve_barcode", code="neon-raider") == "/g/neon-raider"


def test_readonly_is_not_offered_the_round(client, floor):
    login(client, "readonly")
    assert "/round/" not in client.get("/").get_data(as_text=True)
    client.post("/logout")
    login(client, "operator")
    assert "/round/" in client.get("/").get_data(as_text=True)
