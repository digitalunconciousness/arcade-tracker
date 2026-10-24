"""Rail-history pages after Step 4.8b. What they show is pinned by tests/test_rails_views.py;
these cover the fix and the move to layout.html."""
from __future__ import annotations

import re

import pytest
from char_support import login


@pytest.fixture
def partial(floor):
    """F-29: GATBOX can send a mean with no range."""
    from app.extensions import db
    from app.models import RailSession

    s = RailSession.query.filter_by(uid=floor["session_uid"]).one()
    s.powered_min = None
    db.session.commit()
    return floor


def test_a_session_with_a_mean_but_no_range_renders(client, partial):
    login(client, "readonly")
    resp = client.get(f"/rails/session/{partial['session_uid']}")
    html = resp.get_data(as_text=True)
    assert resp.status_code == 200
    assert "5.0100 V" in html, "the mean still shows"


def test_the_machine_history_with_half_a_range_renders(client, partial):
    login(client, "readonly")
    assert client.get("/rails/machine/neon-raider").status_code == 200


@pytest.mark.parametrize("path", ["/rails/", "/rails/machine/neon-raider",
                                  "/rails/session/" + "d" * 32])
def test_the_rails_pages_run_no_inline_script(client, floor, path):
    """Charts come from static/js/rails.js; the page carries only its JSON island."""
    login(client, "readonly")
    html = client.get(path).get_data(as_text=True)
    inline = [m for m in re.findall(r"<script(?![^>]*\bsrc=)([^>]*)>", html)
              if 'type="application/json"' not in m]
    assert not inline
    assert not re.search(r"\son[a-z]+=", html)


def test_report_a_fault_is_offered_only_to_those_who_can_open_it(client, floor):
    """The order form is operator and up (F-31)."""
    fault = f"/maintenance/game/{floor['raider']}"
    login(client, "readonly")
    assert fault not in client.get("/rails/machine/neon-raider").get_data(as_text=True)
    client.post("/logout")
    login(client, "operator")
    assert fault in client.get("/rails/machine/neon-raider").get_data(as_text=True)
