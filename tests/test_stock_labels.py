"""Labels for places and parts, and scanning them (inventory step 1).

Printed labels encode /p/<code> and /i/<code>, and those never change, like /g/<barcode>.
Machine labels are untouched: the Scan page still sends every machine's code to /g/.
Every part and place name is invented.
"""
from __future__ import annotations

import re

import pytest


@pytest.fixture()
def shop(app, client):
    from app.extensions import db
    from app.models import Game, InventoryItem, StockPlace, User

    user = User(username="labeller", role="operator", must_change_password=False)
    user.set_password("not-a-real-password")
    room = StockPlace(name="Dry Storage")
    drawer = StockPlace(name="Low drawer 1", parent=room)
    item = InventoryItem(name="Widget switch", part_number="WS-1", stock_quantity=0)
    game = Game(name="Widget Wars", barcode="widget-wars")
    db.session.add_all([user, room, drawer, item, game])
    db.session.commit()
    client.post("/login", data={"username": "labeller", "password": "not-a-real-password"})
    return {"drawer": drawer.id, "drawer_code": drawer.code, "item": item.id,
            "item_code": item.code}


def test_a_place_label_opens_the_place(client, shop):
    resp = client.get(f"/p/{shop['drawer_code']}")
    assert resp.headers["Location"].endswith(f"/inventory/places/{shop['drawer']}")
    assert client.get(f"/p/{shop['drawer_code'].upper()}").status_code == 302


def test_a_part_label_opens_the_part(client, shop):
    resp = client.get(f"/i/{shop['item_code']}")
    assert resp.headers["Location"].endswith(f"/inventory/{shop['item']}")


@pytest.mark.parametrize("path", ["/p/nosuch", "/i/nosuch"])
def test_an_unknown_code_says_so(client, shop, path):
    resp = client.get(path)
    assert resp.headers["Location"].endswith("/scan")


@pytest.mark.parametrize("path", ["/p/abc", "/i/abc"])
def test_labels_need_a_session(app, path):
    resp = app.test_client().get(path)
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_the_sheet_encodes_the_permanent_addresses(client, shop):
    body = client.get(f"/inventory/labels/sheet?ids=p{shop['drawer']},i{shop['item']}"
                      ).get_data(as_text=True)
    assert f"/p/{shop['drawer_code']}</code>" in body
    assert f"/i/{shop['item_code']}</code>" in body
    assert "Low drawer 1" in body and "Dry Storage" in body       # the name and where it is
    assert "WS-1" in body
    assert len(re.findall(r'class="label-qr" src="data:image/svg\+xml', body)) == 2


def test_a_renamed_place_keeps_its_code(client, shop):
    client.post(f"/inventory/places/{shop['drawer']}/edit", data={"name": "Drawer A"})
    body = client.get(f"/inventory/labels/sheet?ids=p{shop['drawer']}").get_data(as_text=True)
    assert "Drawer A" in body and f"/p/{shop['drawer_code']}" in body


@pytest.mark.parametrize("ids", ["x1", "p", "pabc"])
def test_a_malformed_sheet_link_is_refused(client, shop, ids):
    resp = client.get(f"/inventory/labels/sheet?ids={ids}")
    assert resp.headers["Location"].endswith("/inventory/labels")


def test_the_picker_lists_places_and_parts(client, shop):
    body = client.get("/inventory/labels").get_data(as_text=True)
    assert f'value="p{shop["drawer"]}"' in body and f'value="i{shop["item"]}"' in body


@pytest.mark.parametrize("scanned, lands", [
    ("https://tracker.example.com/p/{drawer_code}", "/p/{drawer_code}"),
    ("https://tracker.example.com/i/{item_code}", "/i/{item_code}"),
    ("{drawer_code}", "/p/{drawer_code}"),
    ("{item_code}", "/i/{item_code}"),
    ("widget-wars", "/g/widget-wars"),
    ("https://tracker.example.com/g/widget-wars", "/g/widget-wars"),
    ("no-such-thing", "/g/no-such-thing"),
])
def test_the_scan_page_sends_each_label_to_its_page(client, shop, scanned, lands):
    resp = client.get("/scan", query_string={"code": scanned.format(**shop)})
    assert resp.headers["Location"].endswith(lands.format(**shop))


def test_a_machine_keeps_its_code_even_if_a_place_shares_it(app, client, shop):
    """A machine's slug wins: /g/ behaves exactly as before places existed."""
    from app.extensions import db
    from app.models import StockPlace

    db.session.get(StockPlace, shop["drawer"]).code = "widget-wars"
    db.session.commit()
    resp = client.get("/scan", query_string={"code": "widget-wars"})
    assert resp.headers["Location"].endswith("/g/widget-wars")


def test_the_place_and_part_pages_link_their_label(client, shop):
    place = client.get(f"/inventory/places/{shop['drawer']}").get_data(as_text=True)
    part = client.get(f"/inventory/{shop['item']}").get_data(as_text=True)
    assert f"/inventory/labels/sheet?ids=p{shop['drawer']}" in place
    assert f"/inventory/labels/sheet?ids=i{shop['item']}" in part
