"""Part details (inventory step 2): categories, units and packs, suppliers, prices, a photo.

Owner's choices, 2026-10-26: a category list managers edit; stock always in the part's unit,
with an optional pack size for buying; suppliers as a list linked to parts with their own
part number, price, pack and link; every price change logged; one photo per part.
Every part and supplier name is invented.
"""
from __future__ import annotations

import io
import os

import pytest
import sqlalchemy as sa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")


def sign_in(app, client, role):
    from app.extensions import db
    from app.models import User

    user = User(username=f"t-{role}", role=role, must_change_password=False)
    user.set_password("not-a-real-password")
    db.session.add(user)
    db.session.commit()
    client.post("/login", data={"username": f"t-{role}", "password": "not-a-real-password"})
    return user.id


@pytest.fixture()
def part(app):
    from app.extensions import db
    from app.models import InventoryItem

    item = InventoryItem(name="Widget switch", stock_quantity=4, minimum_stock=1,
                         unit_price=2.0, supplier="Acme Parts")
    db.session.add(item)
    db.session.commit()
    return item.id


@pytest.fixture()
def manager(app, client, part):
    sign_in(app, client, "manager")
    return client


def item(item_id):
    from app.extensions import db
    from app.models import InventoryItem

    db.session.expire_all()
    return db.session.get(InventoryItem, item_id)


def form(**over):
    data = {"name": "Widget switch", "stock_quantity": "4", "minimum_stock": "1",
            "unit_price": "2.00", "supplier": "Acme Parts", "unit": "", "pack_size": ""}
    data.update(over)
    return data


# --- the part form ------------------------------------------------------------------------

def test_category_unit_and_pack_are_saved(manager, part):
    from app.extensions import db
    from app.models import PartCategory

    fuses = PartCategory(name="Fuses & electrical")
    db.session.add(fuses)
    db.session.commit()
    manager.post(f"/inventory/{part}/edit",
                 data=form(category=str(fuses.id), unit="Roll", pack_size="10"))
    saved = item(part)
    assert (saved.category.name, saved.unit, saved.pack_size) == ("Fuses & electrical", "roll", 10)
    manager.post(f"/inventory/{part}/edit", data=form(category="0", unit="", pack_size="1"))
    saved = item(part)
    assert (saved.category, saved.unit, saved.pack_size) == (None, "each", None)


def test_the_supplier_box_names_the_preferred_supplier(manager, part):
    from app.models import Supplier

    manager.post(f"/inventory/{part}/edit", data=form(supplier="  acme   PARTS "))
    manager.post(f"/inventory/{part}/edit", data=form(supplier="Gizmo Supply"))
    saved = item(part)
    assert saved.supplier == "Gizmo Supply"
    assert sorted(s.name for s in Supplier.query) == ["Gizmo Supply", "acme PARTS"]
    assert [lk.supplier.name for lk in saved.suppliers if lk.preferred] == ["Gizmo Supply"]
    assert len(saved.suppliers) == 2          # the old one is kept, just not preferred


def test_a_price_change_is_logged(manager, part):
    manager.post(f"/inventory/{part}/edit", data=form(unit_price="2.50"))
    manager.post(f"/inventory/{part}/edit", data=form(unit_price="2.50"))   # no change
    [change] = item(part).price_changes
    assert (change.old_price, change.new_price, change.supplier) == (2.0, 2.5, None)
    assert change.user.username == "t-manager"


def test_a_new_part_logs_its_starting_price(manager, part):
    manager.post("/inventory/add", data=form(name="Gadget fuse", unit_price="0.40",
                                             supplier=""))
    from app.models import InventoryItem

    new = InventoryItem.query.filter_by(name="Gadget fuse").one()
    assert [(c.old_price, c.new_price) for c in new.price_changes] == [(None, 0.4)]
    assert new.supplier is None and new.suppliers == []


# --- a part's suppliers -------------------------------------------------------------------

def link(client, part, **data):
    return client.post(f"/inventory/{part}/suppliers/new", data=data)


def test_add_suppliers_with_their_prices(manager, part):
    link(manager, part, supplier="Gizmo Supply", supplier_part_number="GZ-9",
         price="$18.00", pack_size="10", url="gizmo.example.com/gz9")
    saved = item(part)
    gizmo = next(lk for lk in saved.suppliers if lk.supplier.name == "Gizmo Supply")
    assert (gizmo.supplier_part_number, gizmo.price, gizmo.pack_size) == ("GZ-9", 18.0, 10)
    assert gizmo.unit_cost == pytest.approx(1.8)
    assert gizmo.url == "https://gizmo.example.com/gz9"
    # The part's old text supplier isn't a link until its form is saved, so Gizmo is its
    # first supplier, and the first one is preferred.
    assert gizmo.preferred and saved.supplier == "Gizmo Supply"


def test_the_first_supplier_becomes_preferred(manager, part):
    link(manager, part, supplier="Gizmo Supply")
    link(manager, part, supplier="Widget World", preferred="1")
    saved = item(part)
    assert [lk.supplier.name for lk in saved.suppliers if lk.preferred] == ["Widget World"]
    assert saved.supplier == "Widget World"


def test_a_supplier_is_listed_once_per_part(manager, part):
    link(manager, part, supplier="Gizmo Supply")
    link(manager, part, supplier="GIZMO supply")
    assert len(item(part).suppliers) == 1


def test_a_supplier_price_change_is_logged_against_them(manager, part):
    link(manager, part, supplier="Gizmo Supply", price="5")
    lk = item(part).suppliers[0]
    manager.post(f"/inventory/{part}/suppliers/{lk.id}/edit", data={"price": "6.25"})
    changes = [(c.supplier.name, c.old_price, c.new_price) for c in item(part).price_changes]
    assert changes == [("Gizmo Supply", 5.0, 6.25), ("Gizmo Supply", None, 5.0)]


@pytest.mark.parametrize("data", [{"supplier": ""}, {"supplier": "X", "price": "cheap"},
                                  {"supplier": "X", "pack_size": "0"}])
def test_bad_supplier_details_change_nothing(manager, part, data):
    link(manager, part, **data)
    assert item(part).suppliers == []


def test_remove_the_preferred_supplier_and_the_next_takes_over(manager, part):
    link(manager, part, supplier="Gizmo Supply")
    link(manager, part, supplier="Widget World")
    gizmo = next(lk for lk in item(part).suppliers if lk.preferred)
    manager.post(f"/inventory/{part}/suppliers/{gizmo.id}/remove")
    saved = item(part)
    assert [lk.supplier.name for lk in saved.suppliers] == ["Widget World"]
    assert saved.suppliers[0].preferred and saved.supplier == "Widget World"


def test_operators_see_suppliers_but_cannot_change_them(app, client, part):
    sign_in(app, client, "operator")
    link(client, part, supplier="Gizmo Supply")
    assert item(part).suppliers == []
    body = client.get(f"/inventory/{part}").get_data(as_text=True)
    assert "Suppliers" in body and "Add a supplier for this part" not in body


def test_a_link_from_another_part_is_refused(manager, part):
    from app.extensions import db
    from app.models import InventoryItem

    other = InventoryItem(name="Gadget fuse", stock_quantity=0)
    db.session.add(other)
    db.session.commit()
    link(manager, part, supplier="Gizmo Supply")
    lk = item(part).suppliers[0]
    assert manager.post(f"/inventory/{other.id}/suppliers/{lk.id}/remove").status_code == 404


# --- suppliers and categories pages ---------------------------------------------------------

def test_supplier_pages(manager, part):
    from app.models import Supplier

    manager.post("/inventory/suppliers/new", data={"name": "Gizmo Supply"})
    gizmo = Supplier.query.filter_by(name="Gizmo Supply").one()
    manager.post(f"/inventory/suppliers/{gizmo.id}/edit",
                 data={"name": "Gizmo Supply Co", "website": "gizmo.example.com",
                       "phone": "555-0100", "account_number": "A-1"})
    body = manager.get(f"/inventory/suppliers/{gizmo.id}").get_data(as_text=True)
    assert "Gizmo Supply Co" in body and 'href="https://gizmo.example.com"' in body
    manager.post(f"/inventory/suppliers/{gizmo.id}/archive")
    manager.get("/inventory/suppliers")            # shows, and clears, the "Archived" message
    assert "Gizmo Supply Co" not in manager.get("/inventory/suppliers").get_data(as_text=True)


def test_renaming_a_supplier_renames_the_part_text(manager, part):
    from app.models import Supplier

    manager.post(f"/inventory/{part}/edit", data=form(supplier="Gizmo Supply"))
    gizmo = Supplier.query.filter_by(name="Gizmo Supply").one()
    manager.post(f"/inventory/suppliers/{gizmo.id}/edit", data={"name": "Gizmo Co"})
    assert item(part).supplier == "Gizmo Co"


def test_a_website_cannot_be_a_script(manager, part):
    from app.models import Supplier

    manager.post("/inventory/suppliers/new", data={"name": "Gizmo Supply"})
    gizmo = Supplier.query.filter_by(name="Gizmo Supply").one()
    manager.post(f"/inventory/suppliers/{gizmo.id}/edit",
                 data={"name": "Gizmo Supply", "website": "javascript:alert(1)"})
    from app.extensions import db

    db.session.expire_all()
    assert db.session.get(Supplier, gizmo.id).website is None
    manager.post(f"/inventory/suppliers/{gizmo.id}/edit",
                 data={"name": "Gizmo Supply", "website": "localhost:8080/shop"})
    db.session.expire_all()
    assert db.session.get(Supplier, gizmo.id).website == "https://localhost:8080/shop"


def test_categories_are_managed_and_filter_the_list(manager, part):
    from app.models import PartCategory

    manager.post("/inventory/categories/new", data={"name": "Lamps & LEDs"})
    manager.post("/inventory/categories/new", data={"name": "lamps & leds"})
    [lamps] = PartCategory.query.all()
    manager.post(f"/inventory/{part}/edit", data=form(category=str(lamps.id)))
    assert "Widget switch" in manager.get(f"/inventory/?category={lamps.id}").get_data(as_text=True)
    assert "Widget switch" not in manager.get("/inventory/?category=0").get_data(as_text=True)
    manager.post(f"/inventory/categories/{lamps.id}/delete")
    assert item(part).category is None


def test_operators_cannot_edit_categories(app, client, part):
    sign_in(app, client, "operator")
    client.post("/inventory/categories/new", data={"name": "Sneaky"})
    from app.models import PartCategory

    assert PartCategory.query.count() == 0


# --- the photo ----------------------------------------------------------------------------

def png() -> io.BytesIO:
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", (40, 30), (200, 30, 30)).save(buf, "PNG")
    buf.seek(0)
    return buf


def test_a_photo_is_saved_shown_replaced_and_removed(app, manager, part):
    folder = app.config["UPLOAD_FOLDER"]
    manager.post(f"/inventory/{part}/photo", data={"photo": (png(), "switch.png")},
                 content_type="multipart/form-data")
    first = item(part).photo_filename
    assert first.startswith("part_") and first.endswith(".jpg")
    assert os.path.exists(os.path.join(folder, first))
    assert manager.get(f"/inventory/photos/{first}").status_code == 200
    manager.post(f"/inventory/{part}/photo", data={"photo": (png(), "again.png")},
                 content_type="multipart/form-data")
    assert not os.path.exists(os.path.join(folder, first))         # the old file goes
    second = item(part).photo_filename
    manager.post(f"/inventory/{part}/photo/delete")
    assert item(part).photo_filename is None
    assert not os.path.exists(os.path.join(folder, second))


def test_a_file_that_is_not_an_image_is_refused(manager, part):
    manager.post(f"/inventory/{part}/photo",
                 data={"photo": (io.BytesIO(b"not an image"), "switch.png")},
                 content_type="multipart/form-data")
    assert item(part).photo_filename is None


def test_only_part_photos_are_served(manager, part):
    assert manager.get("/inventory/photos/machine_abc.jpg").status_code == 404


# --- the migration ------------------------------------------------------------------------

def test_the_migration_turns_supplier_text_into_suppliers(app):
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    db.session.remove()
    stamp(directory=MIGRATIONS, revision="head")
    downgrade(directory=MIGRATIONS, revision="d9e0f1a2b3c4")
    assert not sa.inspect(db.engine).has_table("supplier")
    with db.engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO inventory_item (name, stock_quantity, minimum_stock, unit_price, supplier)"
            " VALUES ('Widget switch', 1, 0, 2.5, 'Acme Parts'),"
            " ('Gadget fuse', 1, 0, 0, ' acme  parts '), ('Doohickey', 1, 0, 1, NULL)"))
    upgrade(directory=MIGRATIONS, revision="e0f1a2b3c4d5")
    upgrade(directory=MIGRATIONS, revision="e0f1a2b3c4d5")      # a second run changes nothing
    with db.engine.begin() as conn:
        suppliers = conn.execute(sa.text("SELECT name FROM supplier")).all()
        links = conn.execute(sa.text(
            "SELECT i.name, l.price, l.preferred FROM item_supplier l "
            "JOIN inventory_item i ON i.id = l.item_id ORDER BY i.name")).all()
        categories = conn.execute(sa.text("SELECT count(*) FROM part_category")).scalar()
        units = {r[0] for r in conn.execute(sa.text("SELECT unit FROM inventory_item"))}
    assert [s.name for s in suppliers] == ["Acme Parts"]
    assert [(n, p, bool(pref)) for n, p, pref in links] == [
        ("Gadget fuse", None, True), ("Widget switch", 2.5, True)]
    assert categories == 9 and units == {"each"}
