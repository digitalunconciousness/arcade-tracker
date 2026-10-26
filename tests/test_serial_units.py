"""Serialized spares (inventory step 4): units of a part tracked one by one.

A unit is in a place, in a machine, out for repair, or retired, with its own history and
label. Units in a place are that place's stock, so every move keeps the levels right.
Every part, serial, place and machine name is invented.
"""
from __future__ import annotations

import os

import pytest
import sqlalchemy as sa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")


def sign_in(client, role):
    from app.extensions import db
    from app.models import User

    user = User(username=f"t-{role}", role=role, must_change_password=False)
    user.set_password("not-a-real-password")
    db.session.add(user)
    db.session.commit()
    client.post("/login", data={"username": f"t-{role}", "password": "not-a-real-password"})
    return user.id


@pytest.fixture()
def bench(app):
    """A tracked board with 2 on Shelf A from before tracking, a cart, and a machine."""
    from app.extensions import db
    from app.models import Game, InventoryItem, StockLevel, StockPlace

    shelf, cart = StockPlace(name="Shelf A"), StockPlace(name="Tech cart")
    board = InventoryItem(name="Widget CPU board", stock_quantity=2, minimum_stock=1,
                          serialized=True)
    game = Game(name="Widget Wars", barcode="widget-wars")
    db.session.add_all([shelf, cart, board, game])
    db.session.flush()
    db.session.add(StockLevel(item=board, place=shelf, quantity=2))
    db.session.commit()
    return {"shelf": shelf.id, "cart": cart.id, "board": board.id, "game": game.id}


@pytest.fixture()
def operator(client, bench):
    sign_in(client, "operator")
    return client


def board(bench):
    from app.extensions import db
    from app.models import InventoryItem

    db.session.expire_all()
    return db.session.get(InventoryItem, bench["board"])


def levels(item):
    return {lv.place.name: lv.quantity for lv in item.levels if lv.quantity}


def add(client, bench, serials, arriving, where="shelf"):
    return client.post(f"/inventory/{bench['board']}/units/new",
                       data={"serials": serials, "place": str(bench[where]),
                             "arriving": "1" if arriving else "0"})


def unit(bench, serial):
    return next(u for u in board(bench).units if u.serial == serial)


def act(client, u, action, **data):
    return client.post(f"/inventory/units/{u.id}/{action}", data=data)


def test_stock_from_before_is_recorded_without_changing_it(operator, bench):
    body = operator.get(f"/inventory/{bench['board']}").get_data(as_text=True)
    assert "2 in Shelf A without a serial recorded" in body
    add(operator, bench, "WB-001\nWB-002", arriving=False)
    item = board(bench)
    assert item.stock_quantity == 2 and [u.serial for u in item.units] == ["WB-001", "WB-002"]
    assert "without a serial recorded" not in operator.get(
        f"/inventory/{bench['board']}").get_data(as_text=True)


def test_more_than_are_there_cannot_be_recorded(operator, bench):
    add(operator, bench, "A\nB\nC", arriving=False)
    assert board(bench).units == []


def test_new_arrivals_add_stock(operator, bench):
    add(operator, bench, "WB-101, WB-102", arriving=True, where="cart")
    item = board(bench)
    assert item.stock_quantity == 4 and levels(item) == {"Shelf A": 2, "Tech cart": 2}


@pytest.mark.parametrize("serials", ["", "X\nx", "A" * 101])
def test_bad_serials_add_nothing(operator, bench, serials):
    add(operator, bench, serials, arriving=True)
    assert board(bench).units == [] and board(bench).stock_quantity == 2


def test_a_serial_is_used_once_per_part(operator, bench):
    add(operator, bench, "WB-001", arriving=False)
    add(operator, bench, "wb-001", arriving=True)
    assert len(board(bench).units) == 1


def test_a_units_life(operator, bench):
    """Shelf → machine → repair → shelf → cart → retired, with the stock in step."""
    from app.extensions import db
    from app.models import Game

    add(operator, bench, "WB-001\nWB-002", arriving=False)
    act(operator, unit(bench, "WB-001"), "install", game=str(bench["game"]))
    u, item = unit(bench, "WB-001"), board(bench)
    assert (u.state, u.game.name, item.stock_quantity) == ("in_machine", "Widget Wars", 1)
    body = operator.get(f"/game/{bench['game']}").get_data(as_text=True)
    assert "Tracked parts in it" in body and "Serial WB-001" in body

    act(operator, u, "repair", repair_with="Gizmo Repairs")
    u = unit(bench, "WB-001")
    assert (u.state, u.repair_with, board(bench).stock_quantity) == ("at_repair", "Gizmo Repairs", 1)
    assert db.session.get(Game, bench["game"]).serial_units == []

    act(operator, u, "back", place=str(bench["shelf"]))
    act(operator, unit(bench, "WB-001"), "move", place=str(bench["cart"]))
    u, item = unit(bench, "WB-001"), board(bench)
    assert (u.state, u.place.name) == ("in_stock", "Tech cart")
    assert levels(item) == {"Shelf A": 1, "Tech cart": 1}

    act(operator, u, "retire", note="Burnt trace")
    u, item = unit(bench, "WB-001"), board(bench)
    assert u.state == "retired" and item.stock_quantity == 1
    kinds = [e.kind for e in reversed(u.events)]
    assert kinds == ["recorded", "installed", "repair", "returned", "moved", "retired"]
    assert u.events[0].note == "Burnt trace"


def test_taking_a_unit_out_of_a_machine_puts_it_on_a_shelf(operator, bench):
    add(operator, bench, "WB-001", arriving=False)
    act(operator, unit(bench, "WB-001"), "install", game=str(bench["game"]))
    act(operator, unit(bench, "WB-001"), "remove", place=str(bench["cart"]))
    assert levels(board(bench)) == {"Shelf A": 1, "Tech cart": 1}


def test_what_cannot_happen_does_not(operator, bench):
    add(operator, bench, "WB-001", arriving=False)
    u = unit(bench, "WB-001")
    act(operator, u, "remove", place=str(bench["cart"]))             # not in a machine
    act(operator, u, "back", place=str(bench["cart"]))               # not at repair
    act(operator, u, "install", game="")                             # no machine
    act(operator, u, "move", place=str(bench["shelf"]))              # already there
    assert unit(bench, "WB-001").state == "in_stock" and levels(board(bench)) == {"Shelf A": 2}
    assert [e.kind for e in unit(bench, "WB-001").events] == ["recorded"]


def test_a_stock_change_without_the_units_is_flagged(operator, bench):
    from app.extensions import db
    from app.services import stock_places

    add(operator, bench, "WB-001\nWB-002", arriving=False)
    item = board(bench)
    shelf = next(lv.place for lv in item.levels)
    from app.models import User

    stock_places.count(item, 1, User.query.first().id, shelf)
    db.session.commit()
    body = operator.get(f"/inventory/{bench['board']}").get_data(as_text=True)
    assert "2 units recorded in Shelf A, but its stock says 1" in body


def test_tracking_cannot_be_turned_off_with_units_in_service(client, bench):
    sign_in(client, "manager")
    add(client, bench, "WB-001", arriving=False)
    resp = client.post(f"/inventory/{bench['board']}/edit", data={
        "name": "Widget CPU board", "stock_quantity": "2", "minimum_stock": "1"})
    assert resp.status_code == 400 and board(bench).serialized


def test_a_unit_label_and_scanning_it(operator, bench):
    add(operator, bench, "WB-001", arriving=False)
    u = unit(bench, "WB-001")
    sheet = operator.get(f"/inventory/labels/sheet?ids=u{u.id}").get_data(as_text=True)
    assert f"/u/{u.code}</code>" in sheet and "S/N WB-001" in sheet
    assert operator.get(f"/u/{u.code}").headers["Location"].endswith(f"/inventory/units/{u.id}")
    for scanned in (u.code, f"https://tracker.example.com/u/{u.code}"):
        resp = operator.get("/scan", query_string={"code": scanned})
        assert resp.headers["Location"].endswith(f"/u/{u.code}")


def test_managers_correct_a_serial_operators_cannot(client, bench):
    sign_in(client, "operator")
    add(client, bench, "WB-00l", arriving=False)
    u = unit(bench, "WB-00l")
    client.post(f"/inventory/units/{u.id}/edit", data={"serial": "WB-001"})
    assert unit(bench, "WB-00l")
    client.post("/logout")
    sign_in(client, "manager")
    client.post(f"/inventory/units/{u.id}/edit", data={"serial": "WB-001"})
    assert unit(bench, "WB-001").events[0].kind == "edited"


def test_read_only_users_cannot_move_units(app, bench):
    from app.extensions import db
    from app.models import SerialUnit

    client = app.test_client()
    sign_in(client, "readonly")
    u = SerialUnit(item_id=bench["board"], serial="WB-009", place_id=bench["shelf"])
    db.session.add(u)
    db.session.commit()
    client.post(f"/inventory/units/{u.id}/retire")
    assert db.session.get(SerialUnit, u.id).state == "in_stock"


def test_the_migration_adds_tracking_off_for_every_part(app):
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    db.session.remove()
    stamp(directory=MIGRATIONS, revision="head")
    downgrade(directory=MIGRATIONS, revision="f1a2b3c4d5e6")
    assert not sa.inspect(db.engine).has_table("serial_unit")
    items = sa.table("inventory_item", sa.column("name", sa.String),
                     sa.column("stock_quantity", sa.Integer),
                     sa.column("minimum_stock", sa.Integer))
    with db.engine.begin() as conn:
        conn.execute(items.insert().values(name="Widget", stock_quantity=1, minimum_stock=0))
    upgrade(directory=MIGRATIONS, revision="a2b3c4d5e6f7")
    upgrade(directory=MIGRATIONS, revision="a2b3c4d5e6f7")
    with db.engine.begin() as conn:
        flags = [r[0] for r in conn.execute(sa.text("SELECT serialized FROM inventory_item"))]
    assert flags == [False] and sa.inspect(db.engine).has_table("unit_event")
