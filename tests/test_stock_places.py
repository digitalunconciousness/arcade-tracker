"""Where parts are (inventory step 1): places, levels, and the service that changes them.

The rule everything here keeps: a part's ``stock_quantity`` is the sum of its levels, and
every change leaves a history row saying where. Stock from before places is in Unsorted.
Every part and place name is invented.
"""
from __future__ import annotations

import os

import pytest
import sqlalchemy as sa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")


@pytest.fixture()
def shop(app):
    """A user, two places (one nested), and a part that predates places: 10 on the total,
    no levels."""
    from app.extensions import db
    from app.models import InventoryItem, StockPlace, User

    user = User(username="tech", role="operator", must_change_password=False)
    user.set_password("not-a-real-password")
    warehouse = StockPlace(name="Warehouse")
    db.session.add_all([user, warehouse])
    db.session.flush()
    shelf = StockPlace(name="Shelf A", parent=warehouse)
    item = InventoryItem(name="Widget switch", stock_quantity=10, minimum_stock=2)
    db.session.add_all([shelf, item])
    db.session.commit()
    return {"user": user.id, "item": item, "warehouse": warehouse, "shelf": shelf}


def levels(item):
    return {lv.place.name: lv.quantity for lv in item.levels if lv.quantity}


def assert_adds_up(item):
    assert sum(lv.quantity for lv in item.levels) == item.stock_quantity


def test_stock_from_before_places_is_in_unsorted(shop):
    from app.services import stock_places

    item = shop["item"]
    stock_places.add(item, 5, shop["user"], shop["shelf"])
    assert levels(item) == {"Unsorted": 10, "Shelf A": 5}
    assert item.stock_quantity == 15
    assert_adds_up(item)


def test_take_count_and_move_keep_the_total(shop):
    from app.extensions import db
    from app.models import StockHistory
    from app.services import stock_places

    item, shelf, user = shop["item"], shop["shelf"], shop["user"]
    stock_places.move(item, 4, user, stock_places.unsorted_place(), shelf)
    assert item.stock_quantity == 10 and levels(item) == {"Unsorted": 6, "Shelf A": 4}
    stock_places.take(item, 1, user, shelf, kind="used")
    stock_places.count(item, 7, user, shelf)
    db.session.commit()
    assert levels(item) == {"Unsorted": 6, "Shelf A": 7}
    assert item.stock_quantity == 13
    assert_adds_up(item)
    rows = StockHistory.query.filter_by(item_id=item.id).order_by(StockHistory.id).all()
    assert [(r.change_type, r.quantity_change) for r in rows] == [
        ("moved", 4), ("used", -1), ("adjusted", 4)]
    assert rows[0].place.name == "Unsorted" and rows[0].to_place.name == "Shelf A"
    assert all(r.place_id for r in rows)
    assert (rows[-1].previous_quantity, rows[-1].new_quantity) == (9, 13)


def test_taking_more_than_is_there_takes_what_is_there(shop):
    from app.services import stock_places

    item = shop["item"]
    stock_places.add(item, 2, shop["user"], shop["shelf"])
    assert stock_places.take(item, 5, shop["user"], shop["shelf"]) == 2
    with pytest.raises(stock_places.StockError):
        stock_places.take(item, 1, shop["user"], shop["shelf"])
    assert_adds_up(item)


def test_a_work_order_takes_from_unsorted_first(shop):
    from app.services import stock_places

    item = shop["item"]
    stock_places.add(item, 5, shop["user"], shop["shelf"])
    taken = stock_places.take_anywhere(item, 12, shop["user"], "Work order #1")
    assert [(p.name, n) for p, n in taken] == [("Unsorted", 10), ("Shelf A", 2)]
    assert levels(item) == {"Shelf A": 3}
    assert_adds_up(item)


def test_archived_places_take_no_stock(shop):
    from app.services import stock_places

    shop["shelf"].archived = True
    with pytest.raises(stock_places.StockError, match="archived"):
        stock_places.add(shop["item"], 1, shop["user"], shop["shelf"])


def test_moving_to_the_same_place_is_refused(shop):
    from app.services import stock_places

    with pytest.raises(stock_places.StockError):
        stock_places.move(shop["item"], 1, shop["user"], shop["shelf"], shop["shelf"])


def test_a_total_changed_elsewhere_is_reconciled(shop):
    """Older code (or a script) that only sets the total doesn't leave the places wrong."""
    from app.services import stock_places

    item = shop["item"]
    stock_places.add(item, 5, shop["user"], shop["shelf"])
    item.stock_quantity = 3
    stock_places.count(item, 3, shop["user"], shop["shelf"])
    assert levels(item) == {"Shelf A": 3}
    assert_adds_up(item)


def test_the_adjust_form_and_the_edit_form_still_work(shop):
    from app.services import stock_places
    from app.services.inventory import adjust_stock

    item = shop["item"]
    assert adjust_stock(item, "added", 3, "", shop["user"]) == (10, 13)
    assert adjust_stock(item, "removed", 20, "", shop["user"]) == (13, 0)
    assert adjust_stock(item, "adjusted", 6, "", shop["user"]) == (0, 6)
    assert levels(item) == {"Unsorted": 6}
    adjust_stock(item, "moved", 4, "", shop["user"], stock_places.unsorted_place(), shop["shelf"])
    assert adjust_stock(item, "adjusted", 1, "", shop["user"]) == (6, 1)   # the total, no place
    assert adjust_stock(item, "adjusted", 9, "", shop["user"], shop["shelf"]) == (1, 9)
    assert levels(item) == {"Shelf A": 9}
    assert_adds_up(item)


def test_the_tree_nests_and_counts_what_is_below(shop):
    from app.services import stock_places

    stock_places.add(shop["item"], 5, shop["user"], shop["shelf"])
    tree = {n.place.name: n for n in stock_places.place_tree()}
    assert (tree["Warehouse"].depth, tree["Shelf A"].depth) == (0, 1)
    assert (tree["Warehouse"].parts, tree["Warehouse"].units) == (1, 5)
    assert [n.place.name for n in stock_places.place_tree()][-1] == "Unsorted"
    assert shop["shelf"].path == "Warehouse › Shelf A"


def test_a_place_cannot_go_inside_itself_or_unsorted(shop):
    from app.services import stock_places

    with pytest.raises(stock_places.StockError, match="itself"):
        stock_places.check_parent(shop["warehouse"], shop["shelf"])
    with pytest.raises(stock_places.StockError, match="Unsorted"):
        stock_places.check_parent(shop["warehouse"], stock_places.unsorted_place())


def test_places_nest_only_so_deep(shop):
    from app.extensions import db
    from app.models import StockPlace
    from app.models.stock import MAX_DEPTH
    from app.services import stock_places

    place = shop["shelf"]
    for n in range(MAX_DEPTH - 2):
        place = StockPlace(name=f"Bin {n}", parent=place)
        db.session.add(place)
    db.session.flush()
    assert len(place.lineage()) == MAX_DEPTH
    with pytest.raises(stock_places.StockError, match="deep"):
        stock_places.check_parent(None, place)


def test_label_codes_are_made_and_unique(shop):
    from app.models.stock import CODE_ALPHABET

    item, shelf = shop["item"], shop["shelf"]
    assert len(item.code) == 6 and set(item.code) <= set(CODE_ALPHABET)
    assert shelf.code != shop["warehouse"].code


def test_the_migration_puts_todays_stock_in_unsorted(app):
    """Down to before places, two parts with stock as production has them, then up again."""
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    db.session.remove()
    stamp(directory=MIGRATIONS, revision="d9e0f1a2b3c4")
    downgrade(directory=MIGRATIONS, revision="c8d9e0f1a2b3")
    inspector = sa.inspect(db.engine)
    assert not inspector.has_table("stock_place")
    with db.engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO inventory_item (name, stock_quantity, minimum_stock) "
                             "VALUES ('Widget switch', 7, 2), ('Gadget fuse', 0, 1)"))
    upgrade(directory=MIGRATIONS, revision="d9e0f1a2b3c4")
    upgrade(directory=MIGRATIONS, revision="d9e0f1a2b3c4")      # a second run changes nothing
    with db.engine.begin() as conn:
        places = conn.execute(sa.text("SELECT id, name, code FROM stock_place")).all()
        rows = conn.execute(sa.text(
            "SELECT i.name, l.quantity FROM stock_level l JOIN inventory_item i "
            "ON i.id = l.item_id")).all()
        codes = [r[0] for r in conn.execute(sa.text("SELECT code FROM inventory_item"))]
    assert [(p.name, p.code) for p in places] == [("Unsorted", "unsorted")]
    assert rows == [("Widget switch", 7)]
    assert all(codes) and len(set(codes)) == 2
