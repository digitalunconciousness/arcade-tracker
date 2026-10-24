"""Report pages after Step 4.8c: the revenue scope (F-15) and the move to layout.html."""
from __future__ import annotations

import re

import pytest
from char_support import login


@pytest.fixture
def warehouse_revenue(floor):
    """Revenue on a machine that isn't on the Floor (its counter works)."""
    from app.extensions import db
    from app.models import PlayRecord

    db.session.add(PlayRecord(game_id=floor["pinball"], coin_count=10, plays_count=10,
                              revenue=10.0))
    db.session.commit()
    return floor


@pytest.mark.parametrize(("location", "shown", "hidden"), [
    ("", ["Neon Raider"], ["Pixel Pinball"]),                 # the Floor, as it always was
    ("Floor", ["Neon Raider"], ["Pixel Pinball"]),
    ("Warehouse", ["Pixel Pinball"], ["Neon Raider"]),        # F-15: was always empty
    ("all", ["Neon Raider", "Pixel Pinball"], []),
])
def test_the_location_filter_picks_the_machines(client, warehouse_revenue, location, shown,
                                                hidden):
    login(client, "manager")
    html = client.get("/revenue_reports", query_string={"days": 30, "location": location}
                      ).get_data(as_text=True)
    for name in shown:
        assert name in html
    for name in hidden:
        assert name not in html


def test_the_filter_says_what_the_default_is(client, floor):
    login(client, "manager")
    html = client.get("/revenue_reports").get_data(as_text=True)
    assert '<option value="" selected>Floor</option>' in html
    assert '<option value="all">Every location</option>' in html
    assert "Floor · working counters only" in html


def test_the_pdf_uses_the_same_scope(client, warehouse_revenue):
    login(client, "manager")
    resp = client.get("/export_revenue_report?days=30&location=Warehouse")
    assert resp.status_code == 200 and resp.mimetype == "application/pdf"


def test_a_location_that_looks_like_markup_is_not_a_500(client, floor):
    login(client, "manager")
    assert client.get("/export_revenue_report?location=%3Cb%3E").status_code == 200


@pytest.mark.parametrize("path", ["/reports", "/revenue_reports"])
def test_the_report_pages_run_no_inline_script(client, warehouse_revenue, path):
    login(client, "manager")
    html = client.get(path).get_data(as_text=True)
    inline = [m for m in re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", html)
              if 'type="application/json"' not in m]
    assert not inline
    assert not re.search(r"\son[a-z]+=", html)


def test_the_hub_reaches_every_report_without_script(client, floor):
    """The period pickers are GET forms; the PDF buttons send the same period."""
    login(client, "manager")
    html = client.get("/reports").get_data(as_text=True)
    assert 'action="/revenue_reports"' in html and 'action="/maintenance_reports"' in html
    assert 'formaction="/export_maintenance_report"' in html
    assert 'href="/graphs"' in html
