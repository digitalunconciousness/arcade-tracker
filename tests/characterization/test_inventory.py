"""Inventory pages after the redesign (Step 4.5): what each role sees and the fixed bugs."""
from __future__ import annotations

import json
import re

import pytest

from char_support import flashes, login
from test_routes_post import fresh


def page(client, url):
    resp = client.get(url)
    assert resp.status_code == 200, url
    return resp.get_data(as_text=True)


# --- fixed flags ---------------------------------------------------------------------------

def test_receiving_twice_adds_stock_once(client, floor):
    """F-9: re-saving a received request no longer adds its stock again."""
    from app.models import InventoryItem, StockHistory

    login(client, "manager")
    url = f"/inventory/requests/{floor['request']}/update"
    client.post(url, data={"status": "Received"})
    client.post(url, data={"status": "Received", "notes": "Shelved on rack B"})
    assert fresh(InventoryItem, floor["belt"]).stock_quantity == 13
    assert StockHistory.query.filter(StockHistory.item_id == floor["belt"],
                                     StockHistory.reason.like("%received%")).count() == 1


def test_an_update_without_status_keeps_the_status(client, floor):
    """F-9: a POST with no status field keeps the old one."""
    from app.models import InventoryRequest

    login(client, "manager")
    client.post(f"/inventory/requests/{floor['request']}/update", data={"notes": "chased"})
    req = fresh(InventoryRequest, floor["request"])
    assert (req.status, req.notes) == ("Pending", "chased")


def test_an_unknown_status_is_refused(client, floor):
    from app.models import InventoryRequest

    login(client, "manager")
    client.post(f"/inventory/requests/{floor['request']}/update", data={"status": "Lost"})
    assert fresh(InventoryRequest, floor["request"]).status == "Pending"
    assert ("error", "Pick a status from the list.") in flashes(client)


@pytest.mark.parametrize("url", ["/inventory/requests/{request}", "/inventory/requests",
                                 "/inventory/", "/inventory/{belt}"])
def test_no_inline_event_handlers_on_inventory_pages(client, floor, url):
    """F-30: user text never reaches JavaScript; the pages have no on*= attributes at all."""
    from app.extensions import db
    from app.models import InventoryRequest

    fresh(InventoryRequest, floor["request"]).item_name = "O'Brien's belt"
    db.session.commit()
    login(client, "manager")
    html = page(client, url.format(**floor))
    assert not re.findall(r"\son[a-z]+=", html)


def test_an_item_can_be_added_and_counted_down_to_zero(client, floor):
    """F-32: 0 is a stock level, not a missing value."""
    from app.models import InventoryItem

    login(client, "manager")
    client.post("/inventory/add", data={"name": "Back-ordered lamp", "stock_quantity": "0",
                                        "minimum_stock": "0"})
    assert InventoryItem.query.filter_by(name="Back-ordered lamp").count() == 1
    client.get("/logout")
    login(client, "operator")
    client.post(f"/inventory/{floor['belt']}/adjust_stock",
                data={"adjustment_type": "adjusted", "quantity": "0"})
    assert fresh(InventoryItem, floor["belt"]).stock_quantity == 0


def test_the_item_form_has_no_unsaved_fields(client, floor):
    """F-33: category, location and image were shown and never saved."""
    login(client, "manager")
    html = page(client, "/inventory/add")
    for name in ("category", "location", "image"):
        assert f'name="{name}"' not in html


@pytest.mark.parametrize(("kind", "after"), [("damaged", 8), ("returned", 8)])
def test_damaged_and_returned_take_stock_off(client, floor, kind, after):
    """F-38: they fell through to "set the stock to", so writing off 2 left 2 in stock."""
    from app.models import InventoryItem, StockHistory

    login(client, "operator")
    client.post(f"/inventory/{floor['belt']}/adjust_stock",
                data={"adjustment_type": kind, "quantity": "2"})
    assert fresh(InventoryItem, floor["belt"]).stock_quantity == after
    assert StockHistory.query.filter_by(item_id=floor["belt"],
                                        change_type=kind).one().quantity_change == -2


def test_a_part_used_in_a_work_order_is_not_deleted(client, floor):
    """F-39: the delete hit an FK error on PostgreSQL; now it says why and keeps the part."""
    from app.extensions import db
    from app.models import InventoryItem, MaintenanceInventoryUsage

    db.session.add(MaintenanceInventoryUsage(maintenance_id=floor["closed_order"],
                                             item_id=floor["belt"], quantity_used=1,
                                             unit_price_at_time=4.0, total_cost=4.0))
    db.session.commit()
    login(client, "admin")
    resp = client.post(f"/inventory/{floor['belt']}/delete")
    assert resp.headers["Location"] == f"/inventory/{floor['belt']}"
    assert fresh(InventoryItem, floor["belt"]) is not None


def test_deleting_a_part_clears_its_alerts_and_unlinks_its_requests(client, floor):
    from app.models import InventoryItem, InventoryRequest, LowStockAlert

    login(client, "admin")
    client.post(f"/inventory/{floor['fuse']}/delete")
    client.post(f"/inventory/{floor['belt']}/delete")
    assert fresh(InventoryItem, floor["fuse"]) is None
    assert LowStockAlert.query.count() == 0
    req = fresh(InventoryRequest, floor["request"])
    assert (req.item_id, req.item_name) == (None, "Drive Belt")


# --- request form validation ---------------------------------------------------------------

def test_a_bad_request_is_shown_again_with_its_errors(client, floor):
    from app.models import InventoryRequest

    login(client, "operator")
    before = InventoryRequest.query.count()
    resp = client.post("/inventory/request", data={"item_id": "new", "item_name": "",
                                                   "quantity": "0", "reason": "keep me"})
    html = resp.get_data(as_text=True)
    assert resp.status_code == 400
    assert "Name the part." in html and "Ask for at least 1." in html
    assert "keep me" in html
    assert InventoryRequest.query.count() == before


def test_requesting_a_part_that_no_longer_exists_is_refused(client, floor):
    login(client, "operator")
    resp = client.post("/inventory/request", data={"item_id": "99999", "quantity": "1"})
    assert resp.status_code == 400


def test_the_page_form_requests_a_stocked_part_by_id(client, floor):
    """The new page sends item_id only; the name comes from the part, not the form."""
    from app.models import InventoryRequest

    login(client, "operator")
    client.post("/inventory/request", data={"item_id": str(floor["fuse"]), "quantity": "3",
                                            "item_name": "ignored"})
    req = InventoryRequest.query.filter_by(item_id=floor["fuse"]).one()
    assert req.item_name == "Glass Fuse 2A"


def test_a_part_page_preselects_itself_on_the_request_form(client, floor):
    login(client, "operator")
    html = page(client, f"/inventory/request?item_id={floor['fuse']}")
    assert f'<option value="{floor["fuse"]}" selected>' in html


# --- what each role sees -------------------------------------------------------------------

def test_operators_see_no_manager_actions(client, floor):
    login(client, "operator")
    listing = page(client, "/inventory/")
    detail = page(client, f"/inventory/{floor['fuse']}")
    assert "/inventory/add" not in listing and "/inventory/low_stock_alerts" not in listing
    assert "/edit" not in detail and "/delete" not in detail and "resolve_alert" not in detail
    assert f"/inventory/{floor['fuse']}/adjust_stock" in detail


def test_only_admins_see_delete_part(client, floor):
    login(client, "manager")
    assert f"/inventory/{floor['belt']}/delete" not in page(client, f"/inventory/{floor['belt']}")
    client.get("/logout")
    login(client, "admin")
    assert f"/inventory/{floor['belt']}/delete" in page(client, f"/inventory/{floor['belt']}")


def test_the_request_detail_update_returns_to_the_detail(client, floor):
    login(client, "manager")
    resp = client.post(f"/inventory/requests/{floor['request']}/update",
                       data={"status": "Approved", "next": "detail"})
    assert resp.headers["Location"] == f"/inventory/requests/{floor['request']}"


def test_stored_tracking_scans_are_shown(client, floor):
    from app.extensions import db
    from app.models import InventoryRequest

    req = fresh(InventoryRequest, floor["request"])
    req.tracking_number, req.tracking_status = "1Z-SYNTH", "in_transit"
    req.tracking_details = json.dumps({
        "status": "in_transit", "public_url": "javascript:alert(1)",
        "tracking_details": [
            {"datetime": "2026-10-01T09:00:00Z", "status": "pre_transit",
             "message": "Label created", "tracking_location": None},
            {"datetime": "2026-10-02T14:30:00Z", "status": "in_transit",
             "message": "Departed sort facility",
             "tracking_location": {"city": "Springfield", "state": "ZZ"}}]})
    db.session.commit()
    login(client, "manager")
    html = page(client, f"/inventory/requests/{floor['request']}")
    assert "Package is in transit" in html
    assert html.index("Departed sort facility") < html.index("Label created")  # newest first
    assert "Springfield, ZZ" in html
    assert "javascript:" not in html


def test_a_readonly_user_is_kept_out(client, floor):
    login(client, "readonly")
    assert client.get("/inventory/").status_code == 302
