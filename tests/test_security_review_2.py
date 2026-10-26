"""Fixes from the second security review (2026-10-26). Each test fails on the code before
the fix. The double-submit guard in static/js/ui.js is checked in a browser, not here.

Every part, place and machine name is invented.
"""
from __future__ import annotations

import csv
import io
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import login
from seed import seed_floor


@pytest.fixture()
def floor(app):
    return seed_floor()


def get(model, pk):
    from app.extensions import db

    db.session.expire_all()
    return db.session.get(model, pk)


# --- 1. two stock changes at once both count ------------------------------------------------

@pytest.mark.skipif("postgresql" not in os.environ.get("PG_TEST_URL", "")
                    and "postgresql" not in os.environ.get("DATABASE_URL", ""),
                    reason="row locks need PostgreSQL; SQLite writes one request at a time")
def test_two_additions_at_once_are_both_kept(app, floor):
    """The first holds its transaction open after adding; the second adds meanwhile. Without
    the lock the second read the old number, and one addition was lost."""
    from app.extensions import db
    from app.models import InventoryItem, StockPlace, User
    from app.services import stock_places

    user_id = User.query.first().id
    belt, shelf = floor["belt"], floor["shelf"]
    db.session.remove()
    started = threading.Event()
    errors = []

    def add(hold: float):
        try:
            with app.app_context():
                item = db.session.get(InventoryItem, belt)
                stock_places.add(item, 1, user_id, db.session.get(StockPlace, shelf))
                started.set()
                time.sleep(hold)
                db.session.commit()
        except Exception as exc:          # pragma: no cover - shown by the assert below
            errors.append(exc)

    first = threading.Thread(target=add, args=(0.8,))
    first.start()
    started.wait(5)
    second = threading.Thread(target=add, args=(0,))
    second.start()
    first.join(10)
    second.join(10)
    assert errors == []
    item = get(InventoryItem, belt)
    assert item.stock_quantity == 12
    assert sum(lv.quantity for lv in item.levels) == 12


# --- 2. deleting a part or a place leaves nothing pointing at it ---------------------------

def test_deleting_a_part_takes_its_count_lines_and_task_parts(client, floor):
    import datetime as dt

    from app.extensions import db
    from app.models import MaintenanceTask, StockCountLine, TaskPart

    login(client, "admin")
    client.post(f"/inventory/{floor['belt']}/delete")
    assert StockCountLine.query.count() == 0 and TaskPart.query.count() == 0
    assert client.get(f"/inventory/counts/{floor['stock_count']}").status_code == 200
    task = db.session.get(MaintenanceTask, floor["task"])
    task.every_days = 1
    task.created_at = dt.datetime(2025, 1, 1, tzinfo=dt.UTC).replace(tzinfo=None)
    db.session.commit()
    # The task comes due, and its order opens without the part it no longer has.
    assert client.get("/maintenance_orders").status_code == 200


def test_a_place_on_a_count_is_not_deleted(client, floor):
    from app.extensions import db
    from app.models import InventoryItem, StockCount, StockPlace
    from app.services import counts

    bin_ = StockPlace(name="Bin 9")
    db.session.add(bin_)
    db.session.commit()
    count = db.session.get(StockCount, floor["stock_count"])
    counts.add_found(count, db.session.get(InventoryItem, floor["fuse"]), bin_, 2, 1)
    db.session.commit()
    login(client, "manager")
    client.post(f"/inventory/places/{bin_.id}/delete")
    assert get(StockPlace, bin_.id) is not None


# --- 3. only who may see a request may receive it ------------------------------------------

def test_an_operator_cannot_receive_someone_elses_request(client, floor):
    from app.extensions import db
    from app.models import InventoryItem, InventoryRequest, User

    req = db.session.get(InventoryRequest, floor["request"])
    other = User.query.filter_by(username="test-manager").one()
    req.requested_by_id, req.status = other.id, "Ordered"
    db.session.commit()
    login(client, "operator")
    client.post(f"/inventory/requests/{floor['request']}/receive", data={"quantity": "3"})
    assert get(InventoryItem, floor["belt"]).stock_quantity == 10
    assert get(InventoryRequest, floor["request"]).quantity_received == 0


# --- 4. CSV exports don't carry formulas ---------------------------------------------------

@pytest.mark.parametrize("path", ["/export_csv", "/export_selected_games?game_ids={raider}"])
def test_a_machine_name_cannot_become_a_formula(client, floor, path):
    from app.extensions import db
    from app.models import Game

    game = db.session.get(Game, floor["raider"])
    game.name, game.manufacturer = '=HYPERLINK("http://evil.example","x")', "+Widget Co"
    db.session.commit()
    login(client, "manager")
    body = client.get(path.format(**floor)).get_data(as_text=True)
    rows = list(csv.DictReader(io.StringIO(body)))
    row = next(r for r in rows if "HYPERLINK" in r["Game Name"])
    assert row["Game Name"].startswith("'=") and row["Manufacturer"] == "'+Widget Co"
    assert row["Total Plays"].lstrip("-").isdigit()          # numbers untouched


def test_csv_safe_leaves_ordinary_values_alone():
    from app.utils.helpers import csv_safe

    assert [csv_safe(v) for v in ("Neon Raider", 12, -3.5, None, "")] == [
        "Neon Raider", 12, -3.5, None, ""]
    assert [csv_safe(v) for v in ("@SUM(A1)", "-2+3", "\t=1")] == [
        "'@SUM(A1)", "'-2+3", "'\t=1"]


# --- 5. supplier account numbers are for managers ------------------------------------------

def test_operators_do_not_see_account_numbers(client, floor):
    from app.extensions import db
    from app.models import Supplier

    db.session.get(Supplier, floor["supplier"]).account_number = "ACCT-4471"
    db.session.commit()
    login(client, "operator")
    for path in (f"/inventory/suppliers/{floor['supplier']}", f"/inventory/orders/{floor['order']}"):
        assert "ACCT-4471" not in client.get(path).get_data(as_text=True), path
    client.post("/logout")
    login(client, "manager")
    assert "ACCT-4471" in client.get(f"/inventory/suppliers/{floor['supplier']}").get_data(as_text=True)
    assert "ACCT-4471" in client.get(f"/inventory/orders/{floor['order']}").get_data(as_text=True)

