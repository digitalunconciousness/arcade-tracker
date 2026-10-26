"""Preventive maintenance by plays or days (feature step 5).

Owner's decisions (2026-10-25): plays or days, whichever first; a due task raises a playable
work order once; every machine, a type, or one machine; Fixed restarts the count, Deferred
raises it again 7 days later; managers set the tasks up.
"""
from __future__ import annotations

import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import flashes, login
from seed import seed_floor

from app.models.upkeep import _utc_now
from app.services.collection import local_today

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TODAY = local_today()


@pytest.fixture()
def floor(app):
    return seed_floor()


def task(name="Clean the coin mech", *, plays=None, days=None, applies_to="all", game_id=None,
         set_up_days_ago=0, active=True, instructions=None):
    from app.extensions import db
    from app.models import MaintenanceTask

    t = MaintenanceTask(name=name, every_plays=plays, every_days=days, applies_to=applies_to,
                        game_id=game_id, active=active, instructions=instructions,
                        # Backdated from now, not from a fixed hour: just after midnight a
                        # 09:00 "today" would be in the future.
                        created_at=_utc_now() - dt.timedelta(days=set_up_days_ago))
    db.session.add(t)
    db.session.commit()
    return t.id


def pm_orders(task_id=None):
    from app.extensions import db
    from app.models import MaintenanceRecord

    db.session.expire_all()
    q = MaintenanceRecord.query.filter(MaintenanceRecord.source == "pm")
    if task_id:
        q = q.filter_by(pm_task_id=task_id)
    return q.order_by(MaintenanceRecord.id).all()


def read(client, game_id, meter):
    return client.post(f"/record_plays/{game_id}", data={"coin_count": str(meter)})


# --- due by plays -------------------------------------------------------------------------------

def test_a_reading_that_brings_it_due_raises_one_playable_order(client, floor):
    tid = task(plays=50, instructions="Pull the mech and blow it out.")
    login(client, "operator")
    read(client, floor["raider"], 170)                  # 30 plays: not yet
    assert pm_orders(tid) == []
    read(client, floor["raider"], 200)                  # 60 in all
    (order,) = pm_orders(tid)
    assert (order.game_id, order.status, order.machine_down) == (floor["raider"], "Open", False)
    assert order.issue_description.startswith("Preventive maintenance: Clean the coin mech. "
                                              "Due: 60 of 50 plays since the task was set up")
    assert order.issue_description.endswith("Pull the mech and blow it out.")
    assert any(f"work order #{order.id} raised" in m for _, m in flashes(client))
    read(client, floor["raider"], 260)
    assert len(pm_orders(tid)) == 1, "not twice while it's open"


def test_a_round_reading_raises_it_too(client, floor):
    tid = task(plays=10)
    login(client, "operator")
    client.post(f"/round/{floor['raider']}", data={"coin_count": "160"})
    assert len(pm_orders(tid)) == 1


def test_a_playable_order_leaves_the_machine_working(client, floor):
    from app.extensions import db
    from app.models import Game

    task(plays=10)
    login(client, "operator")
    read(client, floor["raider"], 160)
    assert db.session.get(Game, floor["raider"]).status == "Working"


# --- due by days, and whichever first -----------------------------------------------------------

def test_due_by_days_is_raised_when_the_orders_are_opened(client, floor):
    tid = task(days=90, set_up_days_ago=95, applies_to="machine", game_id=floor["raider"])
    login(client, "readonly")
    html = client.get("/maintenance_orders").get_data(as_text=True)
    (order,) = pm_orders(tid)
    assert "Clean the coin mech" in html
    assert "95 of 90 days since the task was set up" in order.issue_description


def test_whichever_comes_first(app, floor):
    from app.services.upkeep import standings

    by_days = task(plays=5000, days=30, set_up_days_ago=31)
    by_plays = task(plays=10, days=365)
    rows = {(s.task.id, s.game.id): s for s in standings()}
    assert rows[(by_days, floor["raider"])].due
    assert not rows[(by_plays, floor["raider"])].due
    assert rows[(by_days, floor["raider"])].share > 1


# --- what it applies to -------------------------------------------------------------------------

def test_what_a_task_applies_to(app, floor):
    from app.extensions import db
    from app.models import Game
    from app.services.upkeep import standings

    flipper = Game(name="Silver Flipper", genre="Pinball", location="Floor", status="Working")
    db.session.add(flipper)
    db.session.commit()
    ids = {k: task(k, days=1, applies_to=k, game_id=floor["courier"] if k == "machine" else None)
           for k in ("all", "pinball", "video", "machine")}
    on = {}
    for s in standings():
        on.setdefault(s.task.id, set()).add(s.game.name)
    assert on[ids["all"]] == {"Neon Raider", "Star Courier", "Silver Flipper"}
    assert on[ids["pinball"]] == {"Silver Flipper"}
    assert on[ids["video"]] == {"Neon Raider", "Star Courier"}
    assert on[ids["machine"]] == {"Star Courier"}
    assert "Pixel Pinball" not in set().union(*on.values()), "the warehouse isn't served"


def test_a_paused_task_raises_nothing(client, floor):
    task(days=1, set_up_days_ago=10, active=False)
    login(client, "operator")
    client.get("/maintenance_orders")
    assert pm_orders() == []


# --- closing the order --------------------------------------------------------------------------

def _close(client, order_id, how):
    client.post(f"/close_maintenance/{order_id}", data={"status": how, "fix_description": "x"})


def test_fixed_starts_the_count_again(client, floor):
    from app.services.upkeep import standings

    tid = task(plays=50)
    login(client, "operator")
    read(client, floor["raider"], 200)
    _close(client, pm_orders(tid)[0].id, "Fixed")
    s = next(s for s in standings() if s.task.id == tid and s.game.id == floor["raider"])
    assert (s.done_before, s.plays, s.state) == (True, 0, "ok"), "today's reading predates it"


def test_deferred_comes_back_a_week_later(client, floor):
    from app.services.upkeep import raise_due, standings

    tid = task(plays=50)
    login(client, "operator")
    read(client, floor["raider"], 200)
    _close(client, pm_orders(tid)[0].id, "Deferred")
    s = next(s for s in standings() if s.task.id == tid and s.game.id == floor["raider"])
    assert (s.state, s.deferred_until) == ("deferred", TODAY + dt.timedelta(7))
    client.get("/maintenance_orders")
    assert len(pm_orders(tid)) == 1
    assert len(raise_due(today=TODAY + dt.timedelta(7))) == 1
    assert len(pm_orders(tid)) == 2


def test_two_requests_at_once_raise_it_once(app, floor):
    """The order's key is unique to task, machine and count: a second insert is skipped."""
    from app.extensions import db
    from app.models import MaintenanceRecord
    from app.services.upkeep import raise_due

    tid = task(days=1, set_up_days_ago=5)
    # What the other request already wrote, as far as the unique key is concerned.
    db.session.add(MaintenanceRecord(game_id=floor["courier"], issue_description="x",
                                     external_id=f"pm-{tid}-{floor['raider']}-1"))
    db.session.commit()
    raised = raise_due()
    assert floor["raider"] not in {o.game_id for o in raised}
    assert floor["courier"] in {o.game_id for o in raised}


# --- the pages ----------------------------------------------------------------------------------

def test_the_page_shows_where_each_machine_stands(client, floor):
    task(plays=1000)
    login(client, "readonly")
    html = client.get("/maintenance/tasks/").get_data(as_text=True)
    assert "Every 1,000 plays" in html and "Neon Raider" in html and "% of the way" in html
    assert "New task" not in html


def test_a_manager_sets_one_up(client, floor):
    from app.models import MaintenanceTask

    login(client, "manager")
    resp = client.post("/maintenance/tasks/new", data={
        "name": "Replace the flipper rubbers", "every_plays": "20,000", "every_days": "",
        "applies_to": "pinball", "active": "1"})
    assert resp.status_code == 302
    t = MaintenanceTask.query.filter_by(name="Replace the flipper rubbers").one()
    assert (t.every_plays, t.every_days, t.applies_to, t.active) == (20000, None, "pinball", True)
    assert t.created_by.username == "test-manager"


@pytest.mark.parametrize(("form", "message"), [
    ({"name": "", "every_days": "30"}, "Name the task"),
    ({"name": "Belt", "every_plays": "", "every_days": ""}, "Give a number of plays"),
    ({"name": "Belt", "every_plays": "0"}, "Between 1 and"),
    ({"name": "Belt", "every_days": "ten"}, "must be a whole number"),
    ({"name": "Belt", "every_days": "30", "applies_to": "machine"}, "Pick the machine"),
])
def test_a_bad_task_is_refused(client, floor, form, message):
    from app.models import MaintenanceTask

    before = MaintenanceTask.query.count()
    login(client, "manager")
    resp = client.post("/maintenance/tasks/new", data={"applies_to": "all", **form})
    assert resp.status_code == 400 and message in resp.get_data(as_text=True)
    assert MaintenanceTask.query.count() == before


def test_deleting_a_task_keeps_its_orders(client, floor):
    tid = task(plays=10)
    login(client, "operator")
    read(client, floor["raider"], 160)
    client.post("/logout")
    login(client, "manager")
    client.post(f"/maintenance/tasks/{tid}/delete")
    (order,) = pm_orders()
    assert order.pm_task_id is None and order.status == "Open"


def test_deleting_a_machine_deletes_its_own_tasks(client, floor):
    from app.models import MaintenanceTask

    own = task(days=30, applies_to="machine", game_id=floor["courier"])
    shared = task(days=30)
    login(client, "admin")
    client.post(f"/delete_game/{floor['courier']}")
    ids = {t.id for t in MaintenanceTask.query.all()}
    assert own not in ids and shared in ids


# --- the migration ------------------------------------------------------------------------------

def test_the_migration_round_trips(app, floor):
    import sqlalchemy as sa
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    def migrate(step, revision):
        db.session.commit()
        step(directory=os.path.join(ROOT, "migrations"), revision=revision)

    def inspect():
        return sa.inspect(db.engine)

    stamp(directory=os.path.join(ROOT, "migrations"), revision="f4a5b6c7d8e9")
    migrate(downgrade, "e3f4a5b6c7d8")
    assert not inspect().has_table("maintenance_task")
    assert "pm_task_id" not in {c["name"] for c in inspect().get_columns("maintenance_record")}
    migrate(upgrade, "f4a5b6c7d8e9")
    migrate(upgrade, "f4a5b6c7d8e9")
    assert inspect().has_table("maintenance_task")
    assert "pm_task_id" in {c["name"] for c in inspect().get_columns("maintenance_record")}
