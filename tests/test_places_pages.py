"""The place pages, and changing stock in a place from the part page (inventory step 1).

Operators make and rename places as they count (owner's choice, 2026-10-26); managers
archive and delete them. Every part and place name is invented.
"""
from __future__ import annotations

import pytest


def sign_in(app, client, role):
    from app.extensions import db
    from app.models import User

    with app.app_context():
        user = User(username=f"t-{role}", role=role, must_change_password=False)
        user.set_password("not-a-real-password")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": f"t-{role}", "password": "not-a-real-password"})
    return client


@pytest.fixture()
def shop(app):
    from app.extensions import db
    from app.models import InventoryItem, StockLevel, StockPlace

    room = StockPlace(name="Dry Storage")
    drawer = StockPlace(name="Low drawer 1", parent=room)
    cart = StockPlace(name="Tech cart")
    item = InventoryItem(name="Widget switch", stock_quantity=6, minimum_stock=1)
    db.session.add_all([room, drawer, cart, item,
                        StockLevel(item=item, place=drawer, quantity=6)])
    db.session.commit()
    return {"room": room.id, "drawer": drawer.id, "cart": cart.id, "item": item.id}


@pytest.fixture()
def operator(app, client):
    return sign_in(app, client, "operator")


@pytest.fixture()
def manager(app, client):
    return sign_in(app, client, "manager")


def place(place_id):
    from app.extensions import db
    from app.models import StockPlace

    db.session.expire_all()
    return db.session.get(StockPlace, place_id)


def by_name(name):
    from app.models import StockPlace

    return StockPlace.query.filter_by(name=name).first()


def levels(item_id):
    from app.extensions import db
    from app.models import InventoryItem

    db.session.expire_all()
    item = db.session.get(InventoryItem, item_id)
    return item.stock_quantity, {lv.place.name: lv.quantity for lv in item.levels if lv.quantity}


def test_the_tree_shows_every_place_nested(operator, shop):
    body = operator.get("/inventory/places/").get_data(as_text=True)
    for name in ("Dry Storage", "Low drawer 1", "Tech cart"):
        assert name in body
    assert "places__row--d1" in body


def test_operators_add_places_as_they_go(operator, shop):
    resp = operator.post("/inventory/places/new",
                         data={"name": "  Shelf   by the door ", "parent": str(shop["room"])})
    new = by_name("Shelf by the door")
    assert new.parent_id == shop["room"]
    assert resp.headers["Location"].endswith(f"/inventory/places/{new.id}")
    operator.post("/inventory/places/new", data={"name": "Warehouse"})
    assert by_name("Warehouse").parent_id is None


def test_a_name_is_used_once_per_place(operator, shop):
    operator.post("/inventory/places/new",
                  data={"name": "low DRAWER 1", "parent": str(shop["room"])})
    assert by_name("low DRAWER 1") is None
    operator.post("/inventory/places/new", data={"name": "Low drawer 1",
                                                 "parent": str(shop["cart"])})
    assert by_name("Low drawer 1") is not None


def test_a_place_page_lists_whats_there(operator, shop):
    body = operator.get(f"/inventory/places/{shop['drawer']}").get_data(as_text=True)
    assert "Widget switch" in body
    assert "Dry Storage" in body          # where it is


def test_rename_and_move_a_place(operator, shop):
    operator.post(f"/inventory/places/{shop['drawer']}/edit",
                  data={"name": "Drawer A", "parent": str(shop["cart"]), "notes": "left side"})
    moved = place(shop["drawer"])
    assert (moved.name, moved.parent_id, moved.notes) == ("Drawer A", shop["cart"], "left side")


def test_a_place_cannot_move_inside_itself(operator, shop):
    operator.post(f"/inventory/places/{shop['room']}/edit",
                  data={"name": "Dry Storage", "parent": str(shop["drawer"])})
    assert place(shop["room"]).parent_id is None


def test_unsorted_keeps_its_name(operator, shop):
    from app.services import stock_places

    unsorted = stock_places.unsorted_place()
    from app.extensions import db

    db.session.commit()
    operator.post(f"/inventory/places/{unsorted.id}/edit", data={"name": "Junk"})
    assert place(unsorted.id).name == "Unsorted"


def test_operators_cannot_archive_or_delete(operator, shop):
    operator.post(f"/inventory/places/{shop['cart']}/archive")
    operator.post(f"/inventory/places/{shop['cart']}/delete")
    assert place(shop["cart"]) is not None and not place(shop["cart"]).archived


def test_read_only_users_see_no_places(app, client, shop):
    sign_in(app, client, "readonly")
    assert client.get("/inventory/places/").status_code in (302, 403)
    client.post("/inventory/places/new", data={"name": "Sneaky"})
    assert by_name("Sneaky") is None


def test_a_place_holding_parts_is_not_archived(manager, shop):
    manager.post(f"/inventory/places/{shop['room']}/archive")
    assert not place(shop["room"]).archived           # the drawer inside holds 6


def test_archiving_takes_the_contents_and_restoring_brings_it_back(manager, shop):
    manager.post("/inventory/places/new", data={"name": "Bin 1", "parent": str(shop["cart"])})
    manager.post(f"/inventory/places/{shop['cart']}/archive")
    assert place(shop["cart"]).archived and by_name("Bin 1").archived
    manager.post(f"/inventory/places/{shop['cart']}/archive")
    assert not place(shop["cart"]).archived


def test_only_an_empty_place_is_deleted(manager, shop):
    manager.post(f"/inventory/places/{shop['drawer']}/delete")
    assert place(shop["drawer"]) is not None
    resp = manager.post(f"/inventory/places/{shop['cart']}/delete")
    assert place(shop["cart"]) is None
    assert resp.headers["Location"].endswith("/inventory/places/")


def test_the_part_page_says_where_it_is(operator, shop):
    body = operator.get(f"/inventory/{shop['item']}").get_data(as_text=True)
    assert "Where it is" in body
    assert "Dry Storage › Low drawer 1" in body
    assert f'<option value="{shop["drawer"]}" selected>' in body


def adjust(client, shop, kind, qty, where=None, to=None):
    data = {"adjustment_type": kind, "quantity": str(qty), "reason": ""}
    if where:
        data["place"] = str(shop[where])
    if to:
        data["to_place"] = str(shop[to])
    return client.post(f"/inventory/{shop['item']}/adjust_stock", data=data)


def test_take_add_count_and_move_in_places(operator, shop):
    adjust(operator, shop, "used", 2, "drawer")
    adjust(operator, shop, "added", 5, "cart")
    adjust(operator, shop, "moved", 3, "drawer", "cart")
    assert levels(shop["item"]) == (9, {"Low drawer 1": 1, "Tech cart": 8})
    adjust(operator, shop, "adjusted", 4, "drawer")
    assert levels(shop["item"]) == (12, {"Low drawer 1": 4, "Tech cart": 8})
    body = operator.get(f"/inventory/{shop['item']}").get_data(as_text=True)
    assert "Dry Storage › Low drawer 1 → Tech cart" in body       # the move, in the history


def test_a_move_needs_somewhere_to_go(operator, shop):
    resp = adjust(operator, shop, "moved", 1, "drawer")
    assert resp.status_code == 400
    assert "where it" in resp.get_data(as_text=True)
    assert levels(shop["item"]) == (6, {"Low drawer 1": 6})


def test_taking_from_an_empty_place_says_so(operator, shop):
    resp = adjust(operator, shop, "removed", 1, "cart")
    assert resp.status_code == 400
    assert "There are none of Widget switch in Tech cart" in resp.get_data(as_text=True)


def test_an_archived_place_is_refused(manager, shop):
    manager.post(f"/inventory/places/{shop['cart']}/archive")
    resp = adjust(manager, shop, "added", 1, "cart")
    assert resp.status_code == 400
    assert levels(shop["item"]) == (6, {"Low drawer 1": 6})
