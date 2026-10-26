"""Inventory meets the rest of the tracker (inventory step 6): work orders take parts from a
place or reserve them; maintenance tasks reserve the parts they need; the machine page
shows its parts; the dashboard and the daily summary say what inventory needs.

Every part, place and machine name is invented.
"""
from __future__ import annotations

import datetime as dt
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
    """A machine with an open order; switches on a shelf (4) and a cart (3)."""
    from app.extensions import db
    from app.models import (
        Game,
        InventoryItem,
        MaintenanceRecord,
        StockLevel,
        StockPlace,
    )

    game = Game(name="Widget Wars", barcode="widget-wars", location="Floor")
    shelf, cart = StockPlace(name="Shelf A"), StockPlace(name="Tech cart")
    switch = InventoryItem(name="Widget switch", stock_quantity=7, minimum_stock=3,
                           unit_price=2.0)
    switch.compatible_games = [game]
    db.session.add_all([game, shelf, cart, switch])
    db.session.flush()
    order = MaintenanceRecord(game_id=game.id, issue_description="Button dead", status="Open")
    db.session.add_all([order, StockLevel(item=switch, place=shelf, quantity=4),
                        StockLevel(item=switch, place=cart, quantity=3)])
    db.session.commit()
    return {"game": game.id, "shelf": shelf.id, "cart": cart.id, "switch": switch.id,
            "order": order.id}


@pytest.fixture()
def operator(client, shop):
    sign_in(client, "operator")
    return client


def get(model, pk):
    from app.extensions import db

    db.session.expire_all()
    return db.session.get(model, pk)


def switch(shop):
    from app.models import InventoryItem

    item = get(InventoryItem, shop["switch"])
    return item.stock_quantity, {lv.place.name: lv.quantity for lv in item.levels}


def log_work(client, shop, action, qty, place=None, status="In_Progress"):
    return client.post(f"/update_maintenance/{shop['order']}", data={
        "status": status, "priority": "Medium", "inventory_item_0": str(shop["switch"]),
        "inventory_quantity_0": str(qty), "item_action_0": action,
        "place_0": str(shop[place]) if place else ""})


# --- work orders take from a place ---------------------------------------------------------

def test_a_part_is_taken_from_the_place_picked(operator, shop):
    log_work(operator, shop, "use", 2, "cart")
    assert switch(shop) == (5, {"Shelf A": 4, "Tech cart": 1})
    from app.models import MaintenanceRecord

    assert get(MaintenanceRecord, shop["order"]).cost == 4.0


def test_more_than_the_place_holds_is_refused(operator, shop):
    log_work(operator, shop, "use", 4, "cart")
    assert switch(shop) == (7, {"Shelf A": 4, "Tech cart": 3})


def test_no_place_takes_from_wherever(operator, shop):
    log_work(operator, shop, "use", 5)
    assert switch(shop)[0] == 2


# --- reservations ---------------------------------------------------------------------------

def test_reserving_holds_parts_without_taking_them(operator, shop):
    from app.models import MaintenanceRecord
    from app.services.reservations import available, reserved

    log_work(operator, shop, "reserve", 3, "shelf")
    order = get(MaintenanceRecord, shop["order"])
    [res] = order.reservations
    assert (res.quantity, res.place.name) == (3, "Shelf A")
    assert switch(shop)[0] == 7 and reserved(res.item) == 3 and available(res.item) == 4
    body = operator.get(f"/inventory/{shop['switch']}").get_data(as_text=True)
    assert "Reserved: 3" in body and "4 are free" in body
    body = operator.get(f"/maintenance_detail/{shop['order']}").get_data(as_text=True)
    assert "Parts reserved" in body and "Widget switch × 3" in body


def test_more_than_is_free_cannot_be_reserved(operator, shop):
    log_work(operator, shop, "reserve", 8)
    from app.models import PartReservation

    assert PartReservation.query.count() == 0


def test_using_a_reservation_takes_it_from_its_place(operator, shop):
    from app.models import MaintenanceRecord

    log_work(operator, shop, "reserve", 2, "cart")
    res = get(MaintenanceRecord, shop["order"]).reservations[0]
    operator.post(f"/maintenance/{shop['order']}/reservations/{res.id}/use")
    order = get(MaintenanceRecord, shop["order"])
    assert order.reservations == [] and order.cost == 4.0
    assert switch(shop) == (5, {"Shelf A": 4, "Tech cart": 1})


def test_releasing_gives_it_back(operator, shop):
    from app.models import MaintenanceRecord

    log_work(operator, shop, "reserve", 2)
    res = get(MaintenanceRecord, shop["order"]).reservations[0]
    operator.post(f"/maintenance/{shop['order']}/reservations/{res.id}/release")
    assert get(MaintenanceRecord, shop["order"]).reservations == []
    assert switch(shop)[0] == 7


@pytest.mark.parametrize("how", ["log", "close"])
def test_closing_the_order_releases_what_was_not_used(operator, shop, how):
    from app.models import MaintenanceRecord

    log_work(operator, shop, "reserve", 2)
    if how == "log":
        operator.post(f"/update_maintenance/{shop['order']}",
                      data={"status": "Fixed", "priority": "Medium"})
    else:
        operator.post(f"/close_maintenance/{shop['order']}", data={"status": "Fixed"})
    order = get(MaintenanceRecord, shop["order"])
    assert order.status == "Fixed" and order.reservations == []
    assert switch(shop)[0] == 7


def test_a_reservation_on_another_order_is_refused(operator, shop):
    from app.extensions import db
    from app.models import MaintenanceRecord

    other = MaintenanceRecord(game_id=shop["game"], issue_description="Other", status="Open")
    db.session.add(other)
    db.session.commit()
    log_work(operator, shop, "reserve", 1)
    res = get(MaintenanceRecord, shop["order"]).reservations[0]
    assert operator.post(f"/maintenance/{other.id}/reservations/{res.id}/use").status_code == 404


def test_reserved_parts_count_as_needed_on_the_shopping_list(app, shop):
    from app.extensions import db
    from app.models import InventoryItem, MaintenanceRecord
    from app.services import purchasing, reservations

    item = db.session.get(InventoryItem, shop["switch"])
    assert purchasing.shopping_list() == []                    # 7 in stock, reorder at 3
    reservations.reserve(db.session.get(MaintenanceRecord, shop["order"]), item, 5, None)
    db.session.commit()
    [group] = purchasing.shopping_list()
    assert group.rows[0].item.name == "Widget switch"
    assert purchasing.suggested(item) == 4                     # up to 6, from 2 free


# --- maintenance task parts -----------------------------------------------------------------

def test_a_task_reserves_its_parts_when_it_opens_an_order(client, shop):
    from app.extensions import db
    from app.models import MaintenanceRecord, MaintenanceTask, TaskPart
    from app.services.upkeep import raise_due

    sign_in(client, "manager")
    client.post("/maintenance/tasks/new", data={
        "name": "Swap the buttons", "every_days": "30", "applies_to": "all", "active": "1",
        "part_item_0": str(shop["switch"]), "part_qty_0": "9"})
    task = MaintenanceTask.query.one()
    assert [(tp.item.name, tp.quantity) for tp in task.parts] == [("Widget switch", 9)]
    task.created_at = dt.datetime(2025, 1, 1, tzinfo=dt.UTC).replace(tzinfo=None)
    db.session.commit()
    [order] = raise_due()
    order = get(MaintenanceRecord, order.id)
    assert [r.quantity for r in order.reservations] == [7]           # all that was free
    assert "Widget switch (2 short)" in order.issue_description
    assert TaskPart.query.count() == 1


def test_the_task_list_shows_its_parts(client, shop):
    from app.extensions import db
    from app.models import MaintenanceTask, TaskPart

    sign_in(client, "manager")
    task = MaintenanceTask(name="Swap the buttons", every_days=30, applies_to="all")
    db.session.add(task)
    db.session.flush()
    db.session.add(TaskPart(task=task, item_id=shop["switch"], quantity=2))
    db.session.commit()
    body = client.get("/maintenance/tasks/").get_data(as_text=True)
    assert "needs Widget switch × 2" in body


# --- the machine page ----------------------------------------------------------------------

def test_the_machine_page_shows_parts_that_fit_and_parts_used(client, shop):
    sign_in(client, "manager")
    log_work(client, shop, "use", 2, "shelf")
    body = client.get(f"/game/{shop['game']}").get_data(as_text=True)
    assert "Parts that fit it" in body and "5 in stock" in body
    assert "Parts it has used · $4.00" in body


def test_operators_see_parts_that_fit_but_not_the_cost(operator, shop):
    log_work(operator, shop, "use", 2)
    body = operator.get(f"/game/{shop['game']}").get_data(as_text=True)
    assert "Parts that fit it" in body and "Parts it has used" not in body


# --- the dashboard and the summary ---------------------------------------------------------

def test_the_dashboard_and_summary_say_what_inventory_needs(client, shop):
    from app.extensions import db
    from app.models import StockCount
    from app.services.alerts import summary_text

    db.session.add(StockCount(name="Shelf check", kind="full", due=dt.date(2026, 1, 1)))
    db.session.commit()
    sign_in(client, "manager")
    body = client.get("/").get_data(as_text=True)
    assert "1 count to do" in body and "1 overdue" in body
    assert "Counts overdue: 1" in summary_text()[1]


# --- the migration ------------------------------------------------------------------------

def test_the_migration_adds_the_tables(app):
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    db.session.remove()
    stamp(directory=MIGRATIONS, revision="head")
    downgrade(directory=MIGRATIONS, revision="b3c4d5e6f7a8")
    assert not sa.inspect(db.engine).has_table("part_reservation")
    upgrade(directory=MIGRATIONS, revision="c4d5e6f7a8b9")
    upgrade(directory=MIGRATIONS, revision="c4d5e6f7a8b9")
    assert sa.inspect(db.engine).has_table("task_part")
