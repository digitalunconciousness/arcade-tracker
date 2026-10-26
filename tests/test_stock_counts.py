"""Planned counts (inventory step 5): full and cycle counts, counted blind, reviewed, applied.

Every part and place name is invented.
"""
from __future__ import annotations

import datetime as dt
import os

import pytest
import sqlalchemy as sa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")


def utc(year, month, day):
    """A naive UTC datetime, as the columns store them."""
    return dt.datetime(year, month, day, tzinfo=dt.UTC).replace(tzinfo=None)


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
def shop(app):
    """A room with a shelf in it, and a cart. Switches on the shelf and the cart, fuses on
    the shelf, a lamp on the cart (counted long ago)."""
    from app.extensions import db
    from app.models import InventoryItem, StockLevel, StockPlace

    room = StockPlace(name="Dry Storage")
    shelf = StockPlace(name="Shelf A", parent=room)
    cart = StockPlace(name="Tech cart")
    switch = InventoryItem(name="Widget switch", stock_quantity=8, minimum_stock=1)
    fuse = InventoryItem(name="Gadget fuse", stock_quantity=20, minimum_stock=1)
    lamp = InventoryItem(name="Doohickey lamp", stock_quantity=3, minimum_stock=1)
    db.session.add_all([room, shelf, cart, switch, fuse, lamp])
    db.session.flush()
    db.session.add_all([
        StockLevel(item=switch, place=shelf, quantity=5,
                   counted=utc(2026, 9, 1)),
        StockLevel(item=switch, place=cart, quantity=3, counted=utc(2026, 9, 1)),
        StockLevel(item=fuse, place=shelf, quantity=20, counted=utc(2026, 10, 1)),
        StockLevel(item=lamp, place=cart, quantity=3, counted=utc(2026, 1, 1)),
    ])
    db.session.commit()
    return {"room": room.id, "shelf": shelf.id, "cart": cart.id, "switch": switch.id,
            "fuse": fuse.id, "lamp": lamp.id}


@pytest.fixture()
def manager(client, shop):
    sign_in(client, "manager")
    return client


def get(model, pk):
    from app.extensions import db

    db.session.expire_all()
    return db.session.get(model, pk)


def levels(shop, key):
    from app.models import InventoryItem

    item = get(InventoryItem, shop[key])
    return item.stock_quantity, {lv.place.name: lv.quantity for lv in item.levels}


def start_full(client, shop, *places, **extra):
    from app.models import StockCount

    client.post("/inventory/counts/new",
                data={"kind": "full", "name": "Storage count",
                      "place": [str(shop[p]) for p in places], **extra})
    return StockCount.query.order_by(StockCount.id.desc()).first()


def line(count, item_key, place_key, shop):
    return next(ln for ln in count.lines
                if ln.item_id == shop[item_key] and ln.place_id == shop[place_key])


def test_a_full_count_takes_the_places_inside(manager, shop):
    count = start_full(manager, shop, "room")
    assert sorted((ln.item.name, ln.place.name, ln.expected) for ln in count.lines) == [
        ("Gadget fuse", "Shelf A", 20), ("Widget switch", "Shelf A", 5)]


def test_counting_is_blind(manager, shop):
    count = start_full(manager, shop, "room")
    body = manager.get(f"/inventory/counts/{count.id}").get_data(as_text=True)
    assert "Widget switch" in body
    assert 'value="5"' not in body and 'value="20"' not in body
    assert "on record" not in body


def test_nothing_changes_until_applied(manager, shop):
    from app.models import StockCount

    count = start_full(manager, shop, "room")
    sw = line(count, "switch", "shelf", shop)
    fu = line(count, "fuse", "shelf", shop)
    manager.post(f"/inventory/counts/{count.id}/save",
                 data={f"line-{sw.id}": "4", f"line-{fu.id}": "20"})
    assert levels(shop, "switch") == (8, {"Shelf A": 5, "Tech cart": 3})
    body = manager.get(f"/inventory/counts/{count.id}/review").get_data(as_text=True)
    assert "-1" in body and "1 matched" in body
    manager.post(f"/inventory/counts/{count.id}/apply")
    assert levels(shop, "switch") == (7, {"Shelf A": 4, "Tech cart": 3})
    assert levels(shop, "fuse") == (20, {"Shelf A": 20})
    count = get(StockCount, count.id)
    assert count.status == "Applied" and count.applied_by.username == "t-manager"
    from app.models import StockHistory, StockLevel

    # The match is marked counted today, with no history row for "no change".
    fuse_level = StockLevel.query.filter_by(item_id=shop["fuse"]).one()
    assert fuse_level.counted.date() >= dt.date(2026, 10, 2)
    assert StockHistory.query.filter_by(item_id=shop["fuse"]).count() == 0
    assert StockHistory.query.filter_by(item_id=shop["switch"]).one().reason == \
        f"Count #{count.id}"


def test_uncounted_lines_are_left_alone(manager, shop):
    count = start_full(manager, shop, "room")
    sw = line(count, "switch", "shelf", shop)
    manager.post(f"/inventory/counts/{count.id}/save", data={f"line-{sw.id}": "6"})
    manager.post(f"/inventory/counts/{count.id}/apply")
    assert levels(shop, "fuse") == (20, {"Shelf A": 20})
    assert levels(shop, "switch")[1]["Shelf A"] == 6


def test_differences_are_against_the_stock_now(manager, shop):
    """Stock that moved while the count was open: the count sets what was counted."""
    from app.extensions import db
    from app.models import InventoryItem, StockPlace
    from app.services import stock_places

    count = start_full(manager, shop, "room")
    sw = line(count, "switch", "shelf", shop)
    manager.post(f"/inventory/counts/{count.id}/save", data={f"line-{sw.id}": "5"})
    from app.models import User

    stock_places.take(db.session.get(InventoryItem, shop["switch"]), 2, User.query.first().id,
                      db.session.get(StockPlace, shop["shelf"]))
    db.session.commit()
    body = manager.get(f"/inventory/counts/{count.id}/review").get_data(as_text=True)
    assert "(was 5)" in body and "+2" in body


def test_found_parts_are_added(manager, shop):
    count = start_full(manager, shop, "room")
    manager.post(f"/inventory/counts/{count.id}/found",
                 data={"part": "doohickey LAMP", "place": str(shop["shelf"]), "quantity": "2"})
    manager.post(f"/inventory/counts/{count.id}/apply")
    assert levels(shop, "lamp") == (5, {"Tech cart": 3, "Shelf A": 2})


def test_a_cycle_count_takes_the_parts_counted_longest_ago(manager, shop):
    from app.models import StockCount

    manager.post("/inventory/counts/new", data={"kind": "cycle", "size": "2"})
    count = StockCount.query.one()
    assert sorted({ln.item.name for ln in count.lines}) == ["Doohickey lamp", "Widget switch"]
    assert len(count.lines) == 3                   # the switch is in two places


def test_a_repeating_count_starts_the_next_when_applied(manager, shop):
    from app.models import StockCount

    count = start_full(manager, shop, "cart", repeat_days="7")
    lamp = line(count, "lamp", "cart", shop)
    manager.post(f"/inventory/counts/{count.id}/save", data={f"line-{lamp.id}": "3"})
    manager.post(f"/inventory/counts/{count.id}/apply")
    nxt = StockCount.query.filter_by(status="Counting").one()
    assert nxt.name == "Storage count" and nxt.repeat_days == 7
    assert nxt.due == get(StockCount, count.id).applied.date() + dt.timedelta(days=7)


def test_a_cancelled_count_changes_nothing(manager, shop):
    from app.models import StockCount

    count = start_full(manager, shop, "room")
    sw = line(count, "switch", "shelf", shop)
    manager.post(f"/inventory/counts/{count.id}/save", data={f"line-{sw.id}": "0"})
    manager.post(f"/inventory/counts/{count.id}/cancel")
    assert get(StockCount, count.id).status == "Cancelled"
    assert levels(shop, "switch")[0] == 8
    manager.post(f"/inventory/counts/{count.id}/save", data={f"line-{sw.id}": "1"})
    assert get(StockCount, count.id).lines[0].counted == 0          # closed: no more saves


@pytest.mark.parametrize("data", [{"kind": "full"}, {"kind": "cycle", "size": "0"},
                                  {"kind": "full", "place": "1", "repeat_days": "400"},
                                  {"kind": "full", "place": "1", "due": "next week"}])
def test_a_bad_start_makes_nothing(manager, shop, data):
    from app.models import StockCount

    manager.post("/inventory/counts/new", data=data)
    assert StockCount.query.count() == 0


def test_operators_count_but_do_not_start_or_apply(client, shop):
    from app.extensions import db
    from app.models import StockCount, StockPlace
    from app.services import counts

    uid = sign_in(client, "operator")
    client.post("/inventory/counts/new", data={"kind": "full", "place": str(shop["room"])})
    assert StockCount.query.count() == 0
    count = counts.start_full("Storage", [db.session.get(StockPlace, shop["room"])], uid)
    db.session.commit()
    sw = line(count, "switch", "shelf", shop)
    client.post(f"/inventory/counts/{count.id}/save", data={f"line-{sw.id}": "4"})
    assert get(StockCount, count.id).counted == 1
    client.post(f"/inventory/counts/{count.id}/apply")
    assert get(StockCount, count.id).status == "Counting"
    assert client.get(f"/inventory/counts/{count.id}/review").status_code in (302, 403)


def test_an_overdue_count_is_flagged(manager, shop):
    count = start_full(manager, shop, "room", due="2026-01-02")
    body = manager.get("/inventory/counts/").get_data(as_text=True)
    assert f"{count.name} was due 2026-01-02" in body


def test_the_migration_adds_the_tables(app):
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    db.session.remove()
    stamp(directory=MIGRATIONS, revision="head")
    downgrade(directory=MIGRATIONS, revision="a2b3c4d5e6f7")
    assert not sa.inspect(db.engine).has_table("stock_count")
    upgrade(directory=MIGRATIONS, revision="b3c4d5e6f7a8")
    upgrade(directory=MIGRATIONS, revision="b3c4d5e6f7a8")
    assert sa.inspect(db.engine).has_table("stock_count_line")
