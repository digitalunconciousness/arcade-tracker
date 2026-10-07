"""What a work order shows: its traces, and where it came from.

Phase 6 (and the tail of Phase 4). An order raised at the bench is only worth having if the
trace that prompted it is one click away, and `maintenance_detail.html` has never linked it.

The two kinds of trace are shown apart on purpose: `rail_session_id` is *why this order
exists*, and `RailSessionTag` rows are what has been measured since. Merging them would lose
that distinction and mean storing the prompting session twice.

`source` is shown because there are now three (`web`, `coindoor`, `gatbox`) and the queue
could not tell a bench order from a customer-facing coin-door report from a hand-typed one.

Every machine and session in these tests is invented.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def signed_in(app, client):
    from app.extensions import db
    from app.models import User

    with app.app_context():
        user = User(username="tester", role="manager")
        user.set_password("not-a-real-password")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "tester",
                                "password": "not-a-real-password"},
                follow_redirects=True)
    return client


@pytest.fixture()
def bench(app):
    """An order prompted by one session, with two more measured since."""
    from app.extensions import db
    from app.models import (Device, Game, MaintenanceRecord, RailSession,
                            RailSessionTag)

    with app.app_context():
        game = Game(name="Widget Wars", barcode="widget-wars")
        device = Device(name="gatbox-01", public_id="a" * 32, token_hash="x")
        db.session.add_all([game, device])
        db.session.commit()
        sessions = []
        for n, uid in enumerate(("1" * 32, "2" * 32, "3" * 32), start=1):
            s = RailSession(uid=uid, device_id=device.id, game_id=game.id,
                            file=f"rail_2026100{n}_010101.csv", verdict="fail")
            sessions.append(s)
        db.session.add_all(sessions)
        db.session.commit()
        order = MaintenanceRecord(game_id=game.id, issue_description="Rail sags under load",
                                 status="Open", source="gatbox", external_id="o" * 32,
                                 rail_session_id=sessions[0].id)
        bare = MaintenanceRecord(game_id=game.id, issue_description="Coin door sticks",
                                 status="Open", source="coindoor")
        legacy = MaintenanceRecord(game_id=game.id, issue_description="Old typed order",
                                   status="Open", source=None)
        db.session.add_all([order, bare, legacy])
        db.session.commit()
        db.session.add_all([
            RailSessionTag(maintenance_record_id=order.id, rail_session_id=sessions[1].id,
                           note="second pass, cold", source="gatbox"),
            RailSessionTag(maintenance_record_id=order.id, rail_session_id=sessions[2].id,
                           source="gatbox"),
        ])
        db.session.commit()
        return {"order": order.id, "bare": bare.id, "legacy": legacy.id,
                "uids": [s.uid for s in sessions]}


def test_the_order_links_the_session_that_prompted_it(signed_in, bench):
    body = signed_in.get(f"/maintenance_detail/{bench['order']}").get_data(as_text=True)
    assert f"/rails/session/{bench['uids'][0]}" in body


def test_it_lists_the_traces_measured_since(signed_in, bench):
    body = signed_in.get(f"/maintenance_detail/{bench['order']}").get_data(as_text=True)
    for uid in bench["uids"][1:]:
        assert f"/rails/session/{uid}" in body


def test_the_two_kinds_are_labelled_apart(signed_in, bench):
    body = signed_in.get(f"/maintenance_detail/{bench['order']}").get_data(as_text=True)
    assert "Prompted by" in body
    assert "Also attached" in body


def test_a_tag_note_is_shown(signed_in, bench):
    body = signed_in.get(f"/maintenance_detail/{bench['order']}").get_data(as_text=True)
    assert "second pass, cold" in body


def test_an_order_with_no_trace_shows_no_link_and_does_not_raise(signed_in, bench):
    response = signed_in.get(f"/maintenance_detail/{bench['bare']}")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "/rails/session/" not in body
    assert "Prompted by" not in body


def test_the_detail_page_says_where_the_order_came_from(signed_in, bench):
    for record_id, expected in ((bench["order"], "bench"), (bench["bare"], "coin door")):
        body = signed_in.get(f"/maintenance_detail/{record_id}").get_data(as_text=True)
        assert expected in body.lower(), expected


def test_a_legacy_order_with_no_source_still_renders(signed_in, bench):
    """Every row that predates Phase 2 has source NULL."""
    assert signed_in.get(f"/maintenance_detail/{bench['legacy']}").status_code == 200


def test_the_queue_says_where_each_order_came_from(signed_in, bench):
    body = signed_in.get("/maintenance_orders").get_data(as_text=True)
    assert response_has(body, "bench")
    assert response_has(body, "coin door")


def response_has(body, text):
    return text in body.lower()


def test_the_queue_renders_with_a_legacy_order_in_it(signed_in, bench):
    assert signed_in.get("/maintenance_orders").status_code == 200


# --- the other direction: a session page listing the orders that cite it -----------------

def test_the_session_page_lists_the_orders_from_it(signed_in, bench):
    """`rails_session.html` has had a "Work orders from this session" block since Phase 4,
    guarded by `{% if orders %}` -- and nothing could put an order on a session until Phase 6
    made it a button, so the block had never rendered. It named an endpoint that does not
    exist (`maintenance.view_maintenance`), so the first session page with an order attached
    answered 500.
    """
    from app.extensions import db
    from app.models import RailSession

    with signed_in.application.app_context():
        uid = db.session.get(RailSession, 1).uid if db.session.get(RailSession, 1) else None
    uid = uid or bench["uids"][0]
    response = signed_in.get(f"/rails/session/{uid}")
    assert response.status_code == 200, response.status_code
    body = response.get_data(as_text=True)
    assert "Work orders from this session" in body
    assert "Rail sags under load" in body


def test_that_link_goes_to_the_order(signed_in, bench):
    body = signed_in.get(f"/rails/session/{bench['uids'][0]}").get_data(as_text=True)
    assert f"/maintenance_detail/{bench['order']}" in body


def test_a_session_with_no_orders_still_renders(signed_in, bench):
    """The guarded branch, the other way round."""
    response = signed_in.get(f"/rails/session/{bench['uids'][2]}")
    assert response.status_code == 200
    assert "Work orders from this session" not in response.get_data(as_text=True)
