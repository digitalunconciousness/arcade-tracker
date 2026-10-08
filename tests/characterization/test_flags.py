"""Known bugs from docs/FEATURES.md §12, each written as the behaviour we want.

Every test here is ``xfail(strict=True)``: it fails today, which proves the bug is real, and
the moment a fix lands it passes, which strict mode turns into a failure until the marker is
removed. So a fix cannot land silently, and a bug cannot quietly come back.

A flag with no test here is either configuration (cookie flags, logging) covered by the
Step 5 security tests, or a decision the owner has not made yet.
"""
from __future__ import annotations

import io
import os
import re
import time

import pytest

from char_support import login
from test_routes_post import fresh, png_bytes


def flag(code: str, why: str):
    return pytest.mark.xfail(strict=True, reason=f"{code}: {why}")


@flag("F-6", "photo cleanup deletes files that work orders still reference")
def test_cleanup_keeps_photos_a_work_order_still_uses(client, floor, sandbox):
    from app.extensions import db
    from app.models import MaintenanceRecord

    photo = sandbox / "static" / "maintenance_photos" / "kept.jpg"
    photo.write_bytes(b"x")
    old = time.time() - 2 * 365 * 86400
    os.utime(photo, (old, old))
    fresh(MaintenanceRecord, floor["closed_order"]).add_photo("kept.jpg")
    db.session.commit()
    login(client, "manager")
    client.post("/admin/cleanup_photos")
    assert photo.exists()


@flag("F-7", "game images are saved to uploads/ but linked from static/uploads/")
def test_an_uploaded_game_image_can_be_displayed(client, floor, sandbox):
    from app.models import Game

    login(client, "operator")
    client.post("/add_game", data={"name": "Image Test", "image": (io.BytesIO(png_bytes()),
                                                                     "cab.png")},
                content_type="multipart/form-data")
    game = Game.query.filter_by(name="Image Test").one()
    html = client.get(f"/game/{game.id}").get_data(as_text=True)
    src = re.search(r'<img src="([^"]+%s)"' % re.escape(game.image_filename), html).group(1)
    assert client.get(src).status_code == 200


@flag("F-8", "an upload Pillow cannot read is still attached to the work order")
def test_a_photo_that_is_not_an_image_is_not_attached(client, floor, sandbox):
    from app.models import MaintenanceRecord

    login(client, "operator")
    client.post(f"/maintenance_photos/{floor['open_order']}", data={
        "csrf_token": "present", "photos": [(io.BytesIO(b"not an image"), "fake.png")]},
        content_type="multipart/form-data")
    assert fresh(MaintenanceRecord, floor["open_order"]).get_photos() == []


@flag("F-9", "re-saving a Received request adds its stock again")
def test_receiving_twice_adds_stock_once(client, floor):
    from app.models import InventoryItem

    login(client, "manager")
    url = f"/inventory/requests/{floor['request']}/update"
    client.post(url, data={"status": "Received"})
    client.post(url, data={"status": "Received", "notes": "Shelved on rack B"})
    assert fresh(InventoryItem, floor["belt"]).stock_quantity == 13


@flag("F-9", "an update without a status field sets the status to None")
def test_an_update_without_status_keeps_the_status(client, floor):
    from app.models import InventoryRequest

    login(client, "manager")
    client.post(f"/inventory/requests/{floor['request']}/update", data={"notes": "chased"})
    assert fresh(InventoryRequest, floor["request"]).status == "Pending"


@flag("F-10", "deleting a game bulk-deletes its orders and orphans their work logs")
def test_deleting_a_game_leaves_no_orphaned_work_logs(client, floor, sandbox):
    from app.models import WorkLog

    login(client, "admin")
    client.post(f"/delete_game/{floor['raider']}")
    assert WorkLog.query.filter_by(maintenance_id=floor["open_order"]).count() == 0


@flag("F-12", "a missing or malformed date on record_plays is a 500")
def test_record_plays_with_a_bad_date_explains_itself(client, floor):
    login(client, "operator")
    resp = client.post(f"/record_plays/{floor['raider']}",
                       data={"coin_count": "150", "date": "yesterday"})
    assert resp.status_code in (200, 302)


@flag("F-12", "a non-numeric year on edit_game is a 500")
def test_edit_game_with_a_bad_year_explains_itself(client, floor, sandbox):
    login(client, "operator")
    resp = client.post(f"/edit_game/{floor['raider']}", data={"name": "Neon Raider",
                                                             "year": "eighty-seven"})
    assert resp.status_code in (200, 302)


@flag("F-12", "ReportLab parses tag-like text (an unclosed <b>, a <br>) as markup: a 500")
def test_a_work_order_pdf_survives_markup_characters(client, floor):
    from app.extensions import db
    from app.models import MaintenanceRecord

    fresh(MaintenanceRecord, floor["open_order"]).issue_description = "Loose wire, see <b>J3"
    db.session.commit()
    login(client, "readonly")
    resp = client.get(f"/download_maintenance_record/{floor['open_order']}")
    assert resp.status_code == 200 and resp.data.startswith(b"%PDF")


@flag("F-15", "the location filter is ANDed with Floor-only, so any other location is empty")
def test_revenue_report_location_filter_can_show_warehouse_revenue(client, floor):
    from app.extensions import db
    from app.models import PlayRecord

    db.session.add(PlayRecord(game_id=floor["pinball"], coin_count=10, plays_count=10,
                              revenue=10.0))
    db.session.commit()
    login(client, "manager")
    html = client.get("/revenue_reports?days=30&location=Warehouse").get_data(as_text=True)
    assert "Pixel Pinball" in html


@flag("F-16", "a readonly user who scans a label is refused instead of seeing the machine")
def test_a_readonly_scan_lands_on_a_page_it_can_read(client, floor):
    login(client, "readonly")
    resp = client.get("/g/neon-raider", follow_redirects=True)
    assert "Neon Raider" in resp.get_data(as_text=True)
    assert "You do not have permission" not in resp.get_data(as_text=True)


@flag("F-17", "any signed-in user, readonly included, can retire a coin-door label")
def test_readonly_cannot_rotate_a_report_token(client, floor):
    from app.extensions import db
    from app.models import Game

    g = fresh(Game, floor["raider"])
    g.mint_report_token()
    db.session.commit()
    token = g.report_token
    login(client, "readonly")
    client.post(f"/game/{floor['raider']}/report-token/rotate")
    assert fresh(Game, floor["raider"]).report_token == token


@flag("F-18", "delete_backup joins a form value onto backups/ with no traversal check")
def test_delete_backup_cannot_leave_the_backup_folder(client, floor, sandbox):
    victim = sandbox / "instance" / "precious.db"
    victim.write_bytes(b"synthetic")
    login(client, "admin")
    client.post("/delete_backup", data={"backup_file": "../instance/precious.db"})
    assert victim.exists()


@flag("F-19", "a password reset sets every account to the same published password")
def test_a_password_reset_does_not_use_a_fixed_password(client, floor):
    from app.models import User

    login(client, "admin")
    client.post("/admin/users", data={"action": "reset_password",
                                      "user_id": floor["users"]["readonly"]})
    assert not fresh(User, floor["users"]["readonly"]).check_password("Arcade123!")


@flag("F-29", "a rail session with a mean but no min/max is a 500 on its page")
def test_a_rail_session_with_partial_figures_renders(client, floor):
    from app.extensions import db
    from app.models import RailSession

    s = RailSession.query.filter_by(uid=floor["session_uid"]).one()
    s.powered_min = s.powered_max = None
    db.session.commit()
    login(client, "readonly")
    assert client.get(f"/rails/session/{floor['session_uid']}").status_code == 200


@flag("F-30", "user text is interpolated into an inline onclick= JavaScript string")
def test_request_detail_keeps_user_text_out_of_event_handlers(client, floor):
    from app.extensions import db
    from app.models import InventoryRequest

    fresh(InventoryRequest, floor["request"]).item_name = "O'Brien's belt"
    db.session.commit()
    login(client, "manager")
    html = client.get(f"/inventory/requests/{floor['request']}").get_data(as_text=True)
    handlers = re.findall(r'\son\w+="([^"]*)"', html)
    assert not any("Brien" in h for h in handlers)


@flag("F-32", "DataRequired on an IntegerField refuses 0, so a zero-stock item is rejected")
def test_an_item_can_be_added_with_zero_stock(client, floor):
    from app.models import InventoryItem

    login(client, "manager")
    client.post("/inventory/add", data={"name": "Back-ordered lamp", "stock_quantity": "0",
                                        "minimum_stock": "0"})
    assert InventoryItem.query.filter_by(name="Back-ordered lamp").count() == 1


@flag("F-34", "send_file resolves backups/ against app/, not the cwd the view checked")
def test_a_backup_can_be_downloaded(client, floor, sandbox):
    (sandbox / "backups" / "arcade_backup_20260101_000000.db").write_bytes(b"SQLite format 3")
    login(client, "admin")
    resp = client.get("/download_backup/arcade_backup_20260101_000000.db")
    assert resp.status_code == 200
