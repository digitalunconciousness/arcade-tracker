"""Location and status history (feature step 1): every change is recorded, however it's made."""
from __future__ import annotations

import io
import json
import os
import sys

import pytest
import sqlalchemy as sa

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import login
from seed import seed_floor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")


@pytest.fixture()
def floor(app):
    return seed_floor()


def events(game_id, kind=None):
    from app.models import GameEvent

    q = GameEvent.query.filter_by(game_id=game_id)
    if kind:
        q = q.filter_by(kind=kind)
    return [(e.kind, e.old_value, e.new_value, e.source, e.user.username if e.user else None)
            for e in q.order_by(GameEvent.id)]


def user_id(name):
    from app.models import User

    return User.query.filter_by(username=name).one().id


def test_adding_a_machine_records_where_it_starts_and_who_added_it(client, floor):
    from app.models import Game

    login(client, "operator")
    client.post("/add_game", data={"name": "Galaxy Runner", "location": "Floor",
                                   "status": "Working"})
    game = Game.query.filter_by(name="Galaxy Runner").one()
    assert events(game.id) == [
        ("location", None, "Floor", "created", "test-operator"),
        ("status", None, "Working", "created", "test-operator"),
    ]


def test_an_edit_records_the_move_with_before_and_after(client, floor):
    login(client, "operator")
    client.post(f"/edit_game/{floor['pinball']}", data={
        "name": "Pixel Pinball", "location": "Floor", "status": "Working"})
    assert events(floor["pinball"], "location")[-1] == (
        "location", "Warehouse", "Floor", "change", "test-operator")
    assert events(floor["pinball"], "status")[-1] == (
        "status", "Not_Working", "Working", "change", "test-operator")


def test_saving_without_a_change_records_nothing(client, floor):
    from app.models import Game

    before = len(events(floor["raider"]))
    game = Game.query.get(floor["raider"])
    login(client, "operator")
    client.post(f"/edit_game/{floor['raider']}", data={
        "name": "Neon Raider renamed", "location": game.location, "status": game.status})
    assert len(events(floor["raider"])) == before, "a rename is not a move"


def test_a_bulk_move_records_each_machine(client, floor):
    login(client, "manager")
    client.post("/bulk_update_games", data={"action": "move_to_warehouse",
                                           "game_ids": [floor["raider"], floor["courier"]]})
    for gid in (floor["raider"], floor["courier"]):
        assert events(gid, "location")[-1] == (
            "location", "Floor", "Warehouse", "change", "test-manager")


def test_a_roster_import_records_new_machines(client, floor):
    from app.models import Game

    roster = {"video_games": [{"name": "Comet Chaser", "slug": "comet-chaser"}]}
    login(client, "manager")
    client.post("/import_games", data={"file": (io.BytesIO(json.dumps(roster).encode()),
                                                "roster.json")},
                content_type="multipart/form-data")
    game = Game.query.filter_by(name="Comet Chaser").one()
    assert [e[3] for e in events(game.id)] == ["created", "created"]


def test_a_change_with_no_signed_in_user_is_still_recorded(app, floor):
    """Scripts and the shell have no user; the change is still history."""
    from app.extensions import db
    from app.models import Game

    game = db.session.get(Game, floor["raider"])
    game.status = "Retired"
    db.session.commit()
    assert events(floor["raider"], "status")[-1][1:] == ("Working", "Retired", "change", None)


def test_the_machine_page_says_where_it_has_been(client, floor):
    login(client, "manager")
    client.post("/bulk_update_games", data={"action": "move_to_floor",
                                           "game_ids": [floor["pinball"]]})
    html = client.get(f"/game/{floor['pinball']}").get_data(as_text=True)
    assert "Where it's been" in html
    assert "Moved from the Warehouse to the Floor" in html and "test-manager" in html


def test_deleting_a_machine_removes_its_history(client, floor):
    from app.models import GameEvent

    assert GameEvent.query.filter_by(game_id=floor["raider"]).count()
    login(client, "admin")
    client.post(f"/delete_game/{floor['raider']}")
    assert GameEvent.query.filter_by(game_id=floor["raider"]).count() == 0


def test_the_migration_gives_existing_machines_a_baseline_once(app, floor):
    """Production machines predate history: each gets 'tracked from here', never a guess."""
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db
    from app.models import Game, GameEvent

    def migrate(step, revision):
        # End the session's transaction first: on PostgreSQL an open read holds a lock on
        # game_event, and the migration's DROP on another connection would wait for ever.
        db.session.commit()
        step(directory=MIGRATIONS, revision=revision)

    GameEvent.query.delete()                      # as if these machines predate the table
    db.session.commit()
    stamp(directory=MIGRATIONS, revision="c7d8e9f0a1b2")
    migrate(upgrade, "d1e2f3a4b5c6")
    games = Game.query.count()
    baselines = GameEvent.query.filter_by(source="baseline")
    assert baselines.count() == 2 * games
    pinball = db.session.get(Game, floor["pinball"])
    assert ("location", None, pinball.location, "baseline", None) in events(pinball.id)

    migrate(downgrade, "c7d8e9f0a1b2")
    assert not sa.inspect(db.engine).has_table("game_event")
    migrate(upgrade, "d1e2f3a4b5c6")
    migrate(upgrade, "d1e2f3a4b5c6")              # nothing more to do
    assert GameEvent.query.filter_by(source="baseline").count() == 2 * games
