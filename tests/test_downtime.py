"""A work order says whether its machine is down, and the machine's status follows (feature step 2).

Owner's decisions (2026-10-25): staff must choose when they raise an order for a machine, and
closing a "down" order as Fixed puts the machine back to Working.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import login
from seed import seed_floor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def floor(app):
    return seed_floor()


def status(game_id):
    from app.extensions import db
    from app.models import Game

    db.session.expire_all()
    return db.session.get(Game, game_id).status


def report(client, game_id, down, issue="Screen is black"):
    data = {"issue_description": issue, "status": "Open", "priority": "Medium"}
    if down is not None:
        data["machine_down"] = "yes" if down else "no"
    return client.post(f"/maintenance/game/{game_id}", data=data)


def newest_order(game_id):
    from app.models import MaintenanceRecord

    return (MaintenanceRecord.query.filter_by(game_id=game_id)
            .order_by(MaintenanceRecord.id.desc()).first())


def update(client, order_id, **form):
    return client.post(f"/update_maintenance/{order_id}", data=form)


def close(client, order_id, how="Fixed"):
    return client.post(f"/close_maintenance/{order_id}", data={"status": how,
                                                               "fix_description": "Done"})


# --- raising an order --------------------------------------------------------------------------

def test_the_choice_is_required_for_a_machine(client, floor):
    from app.models import MaintenanceRecord

    before = MaintenanceRecord.query.count()
    login(client, "operator")
    resp = report(client, floor["courier"], None)
    assert resp.status_code == 400
    assert "Say whether the machine can still be played." in resp.get_data(as_text=True)
    assert MaintenanceRecord.query.count() == before


def test_the_choice_is_offered_with_nothing_preselected(client, floor):
    login(client, "operator")
    html = client.get(f"/game/{floor['courier']}").get_data(as_text=True)
    assert 'name="machine_down" value="yes" required>' in html
    assert 'name="machine_down" value="no">' in html, "neither is checked"


def test_a_down_order_takes_the_machine_down_and_says_which_order(client, floor):
    from app.models import GameEvent

    login(client, "operator")
    report(client, floor["courier"], True)
    order = newest_order(floor["courier"])
    assert order.machine_down is True and status(floor["courier"]) == "Not_Working"
    event = GameEvent.query.filter_by(game_id=floor["courier"], kind="status").order_by(
        GameEvent.id.desc()).first()
    assert (event.old_value, event.new_value, event.maintenance_id, event.user.username) == (
        "Working", "Not_Working", order.id, "test-operator")
    html = client.get(f"/game/{floor['courier']}").get_data(as_text=True)
    assert f"work order #{order.id}" in html


def test_a_playable_order_leaves_the_machine_working(client, floor):
    login(client, "operator")
    report(client, floor["courier"], False, "Left button sticks now and then")
    assert newest_order(floor["courier"]).machine_down is False
    assert status(floor["courier"]) == "Working"


def test_a_general_order_needs_no_choice(client, floor):
    login(client, "operator")
    resp = client.post("/maintenance/general", data={
        "issue_description": "Bar light flickers", "status": "Open",
        "work_order_type": "general", "location_description": "Bar"})
    assert resp.status_code == 302


# --- while it's open, and closing ---------------------------------------------------------------

def test_starting_work_marks_it_being_fixed_and_fixing_it_brings_it_back(client, floor):
    login(client, "operator")
    report(client, floor["courier"], True)
    order = newest_order(floor["courier"])
    update(client, order.id, status="In_Progress")
    assert status(floor["courier"]) == "Being_Fixed"
    close(client, order.id, "Fixed")
    assert status(floor["courier"]) == "Working"


def test_deferring_a_down_order_leaves_it_down(client, floor):
    login(client, "operator")
    report(client, floor["courier"], True)
    close(client, newest_order(floor["courier"]).id, "Deferred")
    assert status(floor["courier"]) == "Not_Working"


def test_it_stays_down_while_another_down_order_is_open(client, floor):
    login(client, "operator")
    report(client, floor["courier"], True, "Screen is black")
    first = newest_order(floor["courier"]).id
    report(client, floor["courier"], True, "Coin mech jammed too")
    second = newest_order(floor["courier"]).id
    close(client, first)
    assert status(floor["courier"]) == "Not_Working"
    close(client, second)
    assert status(floor["courier"]) == "Working"


def test_an_open_order_changed_to_playable_brings_it_back(client, floor):
    login(client, "operator")
    report(client, floor["courier"], True)
    update(client, newest_order(floor["courier"]).id, status="Open", machine_down="no")
    assert status(floor["courier"]) == "Working"


def test_deleting_an_open_down_order_brings_it_back(client, floor):
    login(client, "operator")
    report(client, floor["courier"], True)
    order_id = newest_order(floor["courier"]).id
    client.post("/logout")
    login(client, "manager")
    client.post(f"/delete_maintenance/{order_id}")
    assert status(floor["courier"]) == "Working"


# --- what is never touched ----------------------------------------------------------------------

def test_a_playable_order_never_revives_a_machine_marked_down_by_hand(client, floor):
    """Pixel Pinball is Not_Working with no order saying so; a playable fix isn't the cure."""
    login(client, "operator")
    report(client, floor["pinball"], False, "Flipper rubber worn")
    close(client, newest_order(floor["pinball"]).id)
    assert status(floor["pinball"]) == "Not_Working"


def test_an_older_order_that_never_said_changes_nothing(client, floor):
    """The seeded open order predates the choice (machine_down is NULL)."""
    login(client, "operator")
    assert update(client, floor["open_order"], status="In_Progress").status_code == 302
    close(client, floor["open_order"])
    assert status(floor["raider"]) == "Working"


def test_a_retired_machine_is_never_touched(app, client, floor):
    from app.extensions import db
    from app.models import Game

    db.session.get(Game, floor["courier"]).status = "Retired"
    db.session.commit()
    login(client, "operator")
    report(client, floor["courier"], True)
    assert status(floor["courier"]) == "Retired"


def test_a_coin_door_report_changes_nothing(client, app, floor):
    """Whoever opens the coin door isn't asked; staff decide when they pick it up."""
    from app.extensions import db
    from app.models import Game

    game = db.session.get(Game, floor["courier"])
    token = game.mint_report_token()
    db.session.commit()
    client.post(f"/report/{token}", data={"issue_description": "Screen went black"})
    assert newest_order(floor["courier"]).machine_down is None
    assert status(floor["courier"]) == "Working"


# --- the migration ------------------------------------------------------------------------------

def test_the_migration_adds_the_columns_and_leaves_old_orders_unstated(app, floor):
    import sqlalchemy as sa
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    def columns(table):
        return {c["name"] for c in sa.inspect(db.engine).get_columns(table)}

    def migrate(step, revision):
        db.session.commit()
        step(directory=os.path.join(ROOT, "migrations"), revision=revision)

    stamp(directory=os.path.join(ROOT, "migrations"), revision="e3f4a5b6c7d8")
    migrate(downgrade, "d1e2f3a4b5c6")
    assert "machine_down" not in columns("maintenance_record")
    assert "maintenance_id" not in columns("game_event")
    migrate(upgrade, "e3f4a5b6c7d8")
    migrate(upgrade, "e3f4a5b6c7d8")
    assert "machine_down" in columns("maintenance_record")
    assert "maintenance_id" in columns("game_event")
    assert db.session.execute(sa.text(
        "SELECT count(*) FROM maintenance_record WHERE machine_down IS NOT NULL")).scalar() == 0
