"""Purchasing (inventory step 3): the shopping list, receiving into a place, purchase orders.

Owner's plan, 2026-10-26: reorder points feed a shopping list; the request flow stays;
purchase orders are optional, behind a setting; deliveries can be received in pieces, into
a place. Every part, place and supplier name is invented.
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
def shop(app):
    """Two low parts from two suppliers, one fine part, and a shelf."""
    from app.extensions import db
    from app.models import (
        InventoryItem,
        ItemSupplier,
        StockLevel,
        StockPlace,
        Supplier,
        User,
    )

    buyer = User(username="buyer", role="manager", must_change_password=False)
    buyer.set_password("not-a-real-password")
    gizmo, acme = Supplier(name="Gizmo Supply"), Supplier(name="Acme Parts")
    shelf = StockPlace(name="Shelf A")
    switch = InventoryItem(name="Widget switch", stock_quantity=2, minimum_stock=5,
                           unit_price=1.0)
    fuse = InventoryItem(name="Gadget fuse", stock_quantity=0, minimum_stock=10,
                         reorder_to=50, pack_size=25, unit_price=0.2)
    fine = InventoryItem(name="Doohickey", stock_quantity=20, minimum_stock=3)
    loose = InventoryItem(name="Thingamajig", stock_quantity=0, minimum_stock=0)
    db.session.add_all([buyer, gizmo, acme, shelf, switch, fuse, fine, loose])
    db.session.flush()
    db.session.add_all([
        StockLevel(item=switch, place=shelf, quantity=2),
        ItemSupplier(item=switch, supplier=gizmo, price=1.5, preferred=True),
        ItemSupplier(item=fuse, supplier=acme, price=5.0, pack_size=25, preferred=True),
    ])
    db.session.commit()
    return {"switch": switch.id, "fuse": fuse.id, "fine": fine.id, "loose": loose.id,
            "shelf": shelf.id, "gizmo": gizmo.id, "acme": acme.id, "user": buyer.id}


@pytest.fixture()
def manager(client, shop):
    sign_in(client, "manager")
    return client


def get(model, pk):
    from app.extensions import db

    db.session.expire_all()
    return db.session.get(model, pk)


def part(pk):
    from app.models import InventoryItem

    return get(InventoryItem, pk)


# --- the shopping list --------------------------------------------------------------------

def test_the_list_holds_low_parts_with_a_reorder_level(app, shop):
    from app.services import purchasing

    groups = purchasing.shopping_list()
    names = {g.supplier.name if g.supplier else None: [r.item.name for r in g.rows]
             for g in groups}
    assert names == {"Acme Parts": ["Gadget fuse"], "Gizmo Supply": ["Widget switch"]}


def test_suggestions_top_up_less_what_is_coming_in_whole_packs(app, shop):
    from app.extensions import db
    from app.services import purchasing

    switch, fuse = part(shop["switch"]), part(shop["fuse"])
    assert purchasing.suggested(switch) == 8          # up to 2 x 5, from 2
    assert purchasing.suggested(fuse) == 50           # up to 50, in packs of 25
    req = purchasing.request_from_list(switch, 6, shop["user"])
    db.session.flush()
    assert req.status == "Approved" and req.vendor == "Gizmo Supply"
    assert purchasing.on_order(switch) == 6
    assert purchasing.suggested(switch) == 2


def test_the_page_offers_the_suggestions(manager, shop):
    body = manager.get("/inventory/shopping").get_data(as_text=True)
    assert f'name="qty-{shop["fuse"]}"' in body and 'value="50"' in body
    assert "Put on purchase orders" not in body               # off until turned on


def test_ticked_rows_become_approved_requests(manager, shop):
    from app.models import InventoryRequest

    manager.post("/inventory/shopping/request",
                 data={"item": [str(shop["switch"])], f"qty-{shop['switch']}": "8",
                       f"qty-{shop['fuse']}": "50"})
    [req] = InventoryRequest.query.all()
    assert (req.item_id, req.quantity_requested, req.status) == (shop["switch"], 8, "Approved")


def test_operators_cannot_use_the_shopping_list(client, shop):
    sign_in(client, "operator")
    assert client.get("/inventory/shopping").status_code in (302, 403)


# --- receiving a request ------------------------------------------------------------------

@pytest.fixture()
def request_for_switch(app, shop):
    from app.extensions import db
    from app.services import purchasing

    req = purchasing.request_from_list(part(shop["switch"]), 10, shop["user"])
    db.session.commit()
    return req.id


def receive(client, req_id, **data):
    return client.post(f"/inventory/requests/{req_id}/receive", data=data)


def test_a_delivery_in_two_pieces(manager, shop, request_for_switch):
    from app.models import InventoryRequest

    receive(manager, request_for_switch, quantity="4", place=str(shop["shelf"]))
    req = get(InventoryRequest, request_for_switch)
    assert (req.quantity_received, req.status) == (4, "Approved")
    assert part(shop["switch"]).stock_quantity == 6
    receive(manager, request_for_switch, quantity="6", place=str(shop["shelf"]))
    req = get(InventoryRequest, request_for_switch)
    assert (req.quantity_received, req.status) == (10, "Received")
    assert req.date_fulfilled is not None
    levels = {lv.place.name: lv.quantity for lv in part(shop["switch"]).levels}
    assert levels == {"Shelf A": 12}
    assert receive(manager, request_for_switch, quantity="1").status_code == 302
    assert part(shop["switch"]).stock_quantity == 12            # nothing more after Received


def test_operators_receive_deliveries(client, shop, request_for_switch):
    sign_in(client, "operator")
    receive(client, request_for_switch, quantity="10")
    assert part(shop["switch"]).stock_quantity == 12


def test_a_price_paid_updates_the_supplier_and_optionally_ours(manager, shop, request_for_switch):
    receive(manager, request_for_switch, quantity="5", price="1.75")
    switch = part(shop["switch"])
    assert switch.suppliers[0].price == 1.75 and switch.unit_price == 1.0
    receive(manager, request_for_switch, quantity="5", price="1.80", update_price="1")
    switch = part(shop["switch"])
    assert switch.unit_price == 1.80
    reasons = [c.reason for c in switch.price_changes]
    assert reasons.count(f"Paid on request #{request_for_switch}") == 3


def test_marking_received_adds_only_what_is_still_to_come(manager, shop, request_for_switch):
    receive(manager, request_for_switch, quantity="3", place=str(shop["shelf"]))
    manager.post(f"/inventory/requests/{request_for_switch}/update", data={"status": "Received"})
    assert part(shop["switch"]).stock_quantity == 12            # 2 + 3 + 7, not 2 + 3 + 10


# --- purchase orders ----------------------------------------------------------------------

def orders_on(client):
    client.post("/inventory/shopping/settings", data={"purchase_orders": "on"})


def test_orders_are_off_until_turned_on(manager, shop):
    resp = manager.post("/inventory/shopping/order",
                        data={"item": [str(shop["switch"])], f"qty-{shop['switch']}": "8"})
    assert resp.status_code == 404
    orders_on(manager)
    assert "Put on purchase orders" in manager.get("/inventory/shopping").get_data(as_text=True)


def test_the_list_makes_one_draft_per_supplier(manager, shop):
    from app.models import PurchaseOrder

    orders_on(manager)
    manager.post("/inventory/shopping/order",
                 data={"item": [str(shop["switch"]), str(shop["fuse"])],
                       f"qty-{shop['switch']}": "8", f"qty-{shop['fuse']}": "50"})
    orders = {o.supplier.name: o for o in PurchaseOrder.query.all()}
    assert set(orders) == {"Gizmo Supply", "Acme Parts"}
    [fuse_line] = orders["Acme Parts"].lines
    assert (fuse_line.quantity, fuse_line.unit_price) == (50, pytest.approx(0.2))
    # More from the list joins the same draft.
    manager.post("/inventory/shopping/order",
                 data={"item": [str(shop["switch"])], f"qty-{shop['switch']}": "2"})
    assert PurchaseOrder.query.count() == 2
    assert orders["Gizmo Supply"].lines[0].quantity == 10


def test_a_part_without_a_supplier_is_not_ordered(manager, shop):
    from app.extensions import db
    from app.models import PurchaseOrder

    orders_on(manager)
    fine = part(shop["fine"])
    fine.stock_quantity = 0
    db.session.commit()
    manager.post("/inventory/shopping/order",
                 data={"item": [str(shop["fine"])], f"qty-{shop['fine']}": "5"})
    assert PurchaseOrder.query.count() == 0


@pytest.fixture()
def order(manager, shop):
    from app.extensions import db
    from app.models import Supplier
    from app.services import purchasing

    orders_on(manager)
    po = purchasing.draft_order(db.session.get(Supplier, shop["acme"]), shop["user"])
    purchasing.add_line(po, part(shop["fuse"]), 50)
    db.session.commit()
    return po.id


def test_a_draft_is_edited_then_sent(manager, shop, order):
    from app.models import PurchaseOrder

    po = get(PurchaseOrder, order)
    line = po.lines[0]
    manager.post(f"/inventory/orders/{order}/lines/{line.id}/edit",
                 data={"quantity": "75", "price": "0.18"})
    manager.post(f"/inventory/orders/{order}/lines/new", data={"part": "widget SWITCH",
                                                               "quantity": "4"})
    po = get(PurchaseOrder, order)
    assert [(ln.item.name, ln.quantity, ln.unit_price) for ln in po.lines] == [
        ("Gadget fuse", 75, 0.18), ("Widget switch", 4, None)]
    manager.post(f"/inventory/orders/{order}/send")
    po = get(PurchaseOrder, order)
    assert po.status == "Sent" and po.sent is not None
    manager.post(f"/inventory/orders/{order}/lines/{line.id}/edit", data={"quantity": "1"})
    assert get(PurchaseOrder, order).lines[0].quantity == 75          # sent: no more edits


def test_an_order_arrives_in_pieces(manager, shop, order):
    from app.models import PurchaseOrder
    from app.services import purchasing

    manager.post(f"/inventory/orders/{order}/send")
    line = get(PurchaseOrder, order).lines[0]
    assert purchasing.on_order(part(shop["fuse"])) == 50
    manager.post(f"/inventory/orders/{order}/lines/{line.id}/receive",
                 data={"quantity": "25", "place": str(shop["shelf"])})
    po = get(PurchaseOrder, order)
    assert po.status == "Partly received" and po.lines[0].quantity_received == 25
    assert purchasing.on_order(part(shop["fuse"])) == 25
    manager.post(f"/inventory/orders/{order}/lines/{line.id}/receive", data={"quantity": "25"})
    po = get(PurchaseOrder, order)
    assert po.status == "Received" and po.closed is not None
    fuse = part(shop["fuse"])
    assert fuse.stock_quantity == 50
    assert {lv.place.name: lv.quantity for lv in fuse.levels} == {"Shelf A": 50}


def test_a_draft_cannot_be_received(manager, shop, order):
    from app.models import PurchaseOrder

    line = get(PurchaseOrder, order).lines[0]
    manager.post(f"/inventory/orders/{order}/lines/{line.id}/receive", data={"quantity": "5"})
    assert part(shop["fuse"]).stock_quantity == 0


def test_cancel_and_close(manager, shop, order):
    from app.models import PurchaseOrder

    manager.post(f"/inventory/orders/{order}/send")
    line = get(PurchaseOrder, order).lines[0]
    manager.post(f"/inventory/orders/{order}/lines/{line.id}/receive", data={"quantity": "10"})
    manager.post(f"/inventory/orders/{order}/cancel")
    assert get(PurchaseOrder, order).status == "Partly received"     # something arrived
    manager.post(f"/inventory/orders/{order}/close")
    assert get(PurchaseOrder, order).status == "Received"
    from app.services import purchasing

    assert purchasing.on_order(part(shop["fuse"])) == 0


def test_operators_receive_but_cannot_send(client, shop, order):
    from app.models import PurchaseOrder

    client.post("/logout")
    sign_in(client, "operator")
    client.post(f"/inventory/orders/{order}/send")
    assert get(PurchaseOrder, order).status == "Draft"
    from app.extensions import db
    from app.services import purchasing

    purchasing.send(get(PurchaseOrder, order))
    db.session.commit()
    line = get(PurchaseOrder, order).lines[0]
    client.post(f"/inventory/orders/{order}/lines/{line.id}/receive", data={"quantity": "50"})
    assert part(shop["fuse"]).stock_quantity == 50


def test_a_line_from_another_order_is_refused(manager, shop, order):
    from app.extensions import db
    from app.models import PurchaseOrder, Supplier
    from app.services import purchasing

    other = purchasing.draft_order(db.session.get(Supplier, shop["gizmo"]), shop["user"])
    db.session.commit()
    line = get(PurchaseOrder, order).lines[0]
    assert manager.post(f"/inventory/orders/{other.id}/lines/{line.id}/remove").status_code == 404


def test_a_part_on_an_order_is_not_deleted(app, client, shop, order):
    client.post("/logout")
    sign_in(client, "admin")
    client.post(f"/inventory/{shop['fuse']}/delete")
    assert part(shop["fuse"]) is not None


def test_the_order_page_prints_without_its_forms(manager, shop, order):
    body = manager.get(f"/inventory/orders/{order}").get_data(as_text=True)
    assert "Purchase order #" in body and "data-print" in body
    assert 'class="card stack no-print"' in body


# --- the migration ------------------------------------------------------------------------

def test_the_migration_marks_received_requests_complete(app):
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    db.session.remove()
    stamp(directory=MIGRATIONS, revision="head")
    downgrade(directory=MIGRATIONS, revision="e0f1a2b3c4d5")
    assert not sa.inspect(db.engine).has_table("purchase_order")
    users = sa.table("user", sa.column("id", sa.Integer), sa.column("username", sa.String),
                     sa.column("password_hash", sa.String), sa.column("role", sa.String),
                     sa.column("is_active", sa.Boolean))
    requests = sa.table("inventory_request", sa.column("item_name", sa.String),
                        sa.column("quantity_requested", sa.Integer),
                        sa.column("status", sa.String), sa.column("requested_by_id", sa.Integer))
    with db.engine.begin() as conn:
        conn.execute(users.insert().values(username="someone", password_hash="x",
                                           role="operator", is_active=True))
        uid = conn.execute(sa.select(users.c.id)).scalar()
        conn.execute(requests.insert(), [
            {"item_name": "Widget", "quantity_requested": 6, "status": "Received",
             "requested_by_id": uid},
            {"item_name": "Gadget", "quantity_requested": 4, "status": "Ordered",
             "requested_by_id": uid}])
    upgrade(directory=MIGRATIONS, revision="f1a2b3c4d5e6")
    upgrade(directory=MIGRATIONS, revision="f1a2b3c4d5e6")
    with db.engine.begin() as conn:
        rows = conn.execute(sa.text("SELECT item_name, quantity_received FROM inventory_request "
                                    "ORDER BY item_name")).all()
    assert [tuple(r) for r in rows] == [("Gadget", 0), ("Widget", 6)]
