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


