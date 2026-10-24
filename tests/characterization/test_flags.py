"""Known bugs from docs/FEATURES.md §12, each written as the behaviour we want.

Every test here is ``xfail(strict=True)``: it fails today, which proves the bug is real, and
the moment a fix lands it passes, which strict mode turns into a failure until the marker is
removed. So a fix cannot land silently, and a bug cannot quietly come back.

A flag with no test here is either configuration (cookie flags, logging) covered by the
Step 5 security tests, or a decision the owner has not made yet.
"""
from __future__ import annotations

import pytest

from char_support import login


def flag(code: str, why: str):
    return pytest.mark.xfail(strict=True, reason=f"{code}: {why}")





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





@flag("F-29", "a rail session with a mean but no min/max is a 500 on its page")
def test_a_rail_session_with_partial_figures_renders(client, floor):
    from app.extensions import db
    from app.models import RailSession

    s = RailSession.query.filter_by(uid=floor["session_uid"]).one()
    s.powered_min = s.powered_max = None
    db.session.commit()
    login(client, "readonly")
    assert client.get(f"/rails/session/{floor['session_uid']}").status_code == 200
