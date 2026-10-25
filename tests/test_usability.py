"""The usability round: who reported and fixed an order, the machine page's buttons and photo,
and a home screen per role. Owner's decisions of 2026-10-25."""
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


def newest(game_id):
    from app.extensions import db
    from app.models import MaintenanceRecord

    db.session.expire_all()
    return (MaintenanceRecord.query.filter_by(game_id=game_id)
            .order_by(MaintenanceRecord.id.desc()).first())


def report(client, game_id, **extra):
    data = {"issue_description": "Screen is black", "status": "Open", "machine_down": "no",
            **extra}
    return client.post(f"/maintenance/game/{game_id}", data=data)


# --- who reported it, who fixed it --------------------------------------------------------------

def test_a_signed_in_report_records_who(client, floor):
    login(client, "operator")
    report(client, floor["courier"])
    order = newest(floor["courier"])
    assert order.reported_by_user.username == "test-operator"
    html = client.get(f"/maintenance_detail/{order.id}").get_data(as_text=True)
    assert "Reported by</dt><dd>test-operator" in html


def test_closing_as_fixed_records_who_and_the_machine_page_says_so(client, floor):
    login(client, "operator")
    report(client, floor["courier"])
    order = newest(floor["courier"])
    client.post(f"/close_maintenance/{order.id}", data={
        "status": "Fixed", "fix_description": "Reseated the video cable", "technician": ""})
    order = newest(floor["courier"])
    assert order.fixed_by_user.username == "test-operator"
    html = client.get(f"/game/{floor['courier']}").get_data(as_text=True)
    assert "Last fixed" in html and "Reseated the video cable" in html
    assert "by test-operator" in html


def test_deferring_isnt_fixing(client, floor):
    login(client, "operator")
    report(client, floor["courier"])
    order = newest(floor["courier"])
    client.post(f"/close_maintenance/{order.id}", data={"status": "Deferred",
                                                        "fix_description": "Later"})
    assert newest(floor["courier"]).fixed_by_id is None


def test_an_older_order_falls_back_to_its_technician(client, floor):
    """The seeded closed order predates the column: its technician is who fixed it."""
    login(client, "readonly")
    html = client.get(f"/game/{floor['raider']}").get_data(as_text=True)
    assert "Last fixed" in html and "Cleared the chute" in html


def test_everyone_sees_how_it_was_fixed_last_time(client, floor):
    login(client, "readonly")
    assert "Last fixed" in client.get(f"/game/{floor['raider']}").get_data(as_text=True)


@pytest.mark.parametrize(("source", "name", "expected"), [
    ("coindoor", "Sam Tester", "Sam Tester, at the coin door"),
    ("coindoor", None, "The coin door"),
    ("gatbox", None, "GATBOX"),
    ("pm", None, "Preventive maintenance"),
    ("web", None, None),
])
def test_how_a_reporter_reads(app, source, name, expected):
    from app.models import MaintenanceRecord

    assert MaintenanceRecord(source=source, reported_by=name).reporter == expected


def test_the_migration_round_trips(app, floor):
    import sqlalchemy as sa
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    def migrate(step, revision):
        db.session.commit()
        step(directory=os.path.join(ROOT, "migrations"), revision=revision)

    def columns():
        return {c["name"] for c in sa.inspect(db.engine).get_columns("maintenance_record")}

    new = {"reported_by", "reported_by_id", "fixed_by_id"}
    stamp(directory=os.path.join(ROOT, "migrations"), revision="b6c7d8e9f0a1")
    migrate(downgrade, "a5b6c7d8e9f0")
    assert not new & columns()
    migrate(upgrade, "b6c7d8e9f0a1")
    migrate(upgrade, "b6c7d8e9f0a1")
    assert new <= columns()
