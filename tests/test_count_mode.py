"""Count mode: the first inventory, done place by place on a phone (owner's choice,
2026-10-26: count as you go, new parts made on the spot with just a name).

Every part and place name is invented.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def drawer(app, client):
    from app.extensions import db
    from app.models import InventoryItem, StockLevel, StockPlace, User

    user = User(username="counter", role="operator", must_change_password=False)
    user.set_password("not-a-real-password")
    room = StockPlace(name="Dry Storage")
    drawer = StockPlace(name="Low drawer 1", parent=room)
    switch = InventoryItem(name="Widget switch", part_number="WS-1", stock_quantity=5,
                           minimum_stock=1)
    fuse = InventoryItem(name="Gadget fuse", stock_quantity=2, minimum_stock=0)
    db.session.add_all([user, room, drawer, switch, fuse,
                        StockLevel(item=switch, place=drawer, quantity=5)])
    db.session.commit()
    client.post("/login", data={"username": "counter", "password": "not-a-real-password"})
    return {"place": drawer.id, "room": room.id, "switch": switch.id, "fuse": fuse.id,
            "fuse_code": fuse.code}


def where(item_id):
    from app.extensions import db
    from app.models import InventoryItem

    db.session.expire_all()
    item = db.session.get(InventoryItem, item_id)
    return item.stock_quantity, {lv.place.name: lv.quantity for lv in item.levels}


def url(drawer, tail=""):
    return f"/inventory/places/{drawer['place']}/count{tail}"


def test_the_page_lists_what_is_here_with_a_box_each(client, drawer):
    body = client.get(url(drawer)).get_data(as_text=True)
    assert "Widget switch" in body and "5 on record" in body
    assert f'name="count-{drawer["switch"]}"' in body
    assert "data-camera-input=\"count-part\"" in body
    assert '<option value="Gadget fuse">' in body      # every part, for the name box


def test_a_typed_count_is_saved_and_a_blank_box_is_left_alone(client, drawer):
    from app.models import StockLevel

    client.post(url(drawer), data={f"count-{drawer['switch']}": "3"})
    assert where(drawer["switch"]) == (3, {"Low drawer 1": 3})
    level = StockLevel.query.filter_by(item_id=drawer["switch"], place_id=drawer["place"]).one()
    assert level.counted is not None
    client.post(url(drawer), data={f"count-{drawer['switch']}": ""})
    assert where(drawer["switch"]) == (3, {"Low drawer 1": 3})


def test_zero_is_a_count_and_the_part_stays_listed(client, drawer):
    client.post(url(drawer), data={f"count-{drawer['switch']}": "0"})
    assert where(drawer["switch"]) == (0, {"Low drawer 1": 0})
    assert "Widget switch" in client.get(url(drawer)).get_data(as_text=True)


def test_a_bad_number_saves_nothing(client, drawer):
    client.post(url(drawer), data={f"count-{drawer['switch']}": "3x"})
    assert where(drawer["switch"]) == (5, {"Low drawer 1": 5})


@pytest.mark.parametrize("typed", ["gadget FUSE", "{code}", "https://tracker.example.com/i/{code}"])
def test_add_a_known_part_by_name_or_label(client, drawer, typed):
    client.post(url(drawer, "/add"),
                data={"part": typed.format(code=drawer["fuse_code"]), "quantity": "4"})
    # Its 2 from before places were in Unsorted; the drawer now has 4 more.
    assert where(drawer["fuse"]) == (6, {"Unsorted": 2, "Low drawer 1": 4})


def test_add_by_part_number(client, drawer):
    client.post(url(drawer, "/add"), data={"part": "ws-1", "quantity": "7"})
    assert where(drawer["switch"]) == (7, {"Low drawer 1": 7})


def test_an_unknown_name_asks_before_making_a_part(client, drawer):
    from app.models import InventoryItem

    body = client.post(url(drawer, "/add"),
                       data={"part": "Doohickey spring", "quantity": "9"}).get_data(as_text=True)
    assert "No part called “Doohickey spring”" in body
    assert InventoryItem.query.filter_by(name="Doohickey spring").count() == 0
    client.post(url(drawer, "/add"),
                data={"part": "Doohickey spring", "quantity": "9", "create": "1"})
    made = InventoryItem.query.filter_by(name="Doohickey spring").one()
    assert where(made.id) == (9, {"Low drawer 1": 9})
    assert made.minimum_stock == 0 and made.code


@pytest.mark.parametrize("data", [{"part": "Widget switch", "quantity": ""},
                                  {"part": "", "quantity": "3"},
                                  {"part": "Widget switch", "quantity": "-1"}])
def test_add_needs_a_part_and_a_number(client, drawer, data):
    resp = client.post(url(drawer, "/add"), data=data)
    assert resp.status_code == 400
    assert where(drawer["switch"]) == (5, {"Low drawer 1": 5})


def test_a_new_place_from_count_mode_opens_its_count(client, drawer):
    from app.models import StockPlace

    resp = client.post("/inventory/places/new", data={"name": "Bin 3", "parent": str(drawer["place"]),
                                                      "back": "count"})
    made = StockPlace.query.filter_by(name="Bin 3").one()
    assert resp.headers["Location"].endswith(f"/inventory/places/{made.id}/count")


def test_an_archived_place_is_not_counted(app, client, drawer):
    from app.extensions import db
    from app.models import StockPlace

    db.session.get(StockPlace, drawer["place"]).archived = True
    db.session.commit()
    assert client.get(url(drawer)).status_code == 302
    client.post(url(drawer), data={f"count-{drawer['switch']}": "1"})
    assert where(drawer["switch"]) == (5, {"Low drawer 1": 5})


def test_the_place_page_offers_count_mode(client, drawer):
    body = client.get(f"/inventory/places/{drawer['place']}").get_data(as_text=True)
    assert url(drawer) in body
