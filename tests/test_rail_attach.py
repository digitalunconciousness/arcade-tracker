"""From a rail reading to a work order, in the web app.

The bench could already tag a session onto an order (GATBOX's `session_tag`), but someone
looking at a reading in the browser had no way to do either (owner's request, 2026-10-26):
add it to one of the machine's open orders, or open a new order with it as the reading
that prompted it.

Every machine and session in these tests is invented.
"""
from __future__ import annotations

import pytest


def sign_in(app, client, role):
    from app.extensions import db
    from app.models import User

    with app.app_context():
        user = User(username=f"t-{role}", role=role, must_change_password=False)
        user.set_password("not-a-real-password")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": f"t-{role}", "password": "not-a-real-password"})
    return client


@pytest.fixture()
def operator(app, client):
    return sign_in(app, client, "operator")


@pytest.fixture()
def bench(app):
    """Two machines, a reading on the first, and orders open and closed on both."""
    from app.extensions import db
    from app.models import Device, Game, MaintenanceRecord, RailSession

    with app.app_context():
        widget = Game(name="Widget Wars", barcode="widget-wars")
        gadget = Game(name="Gadget Galaxy", barcode="gadget-galaxy")
        device = Device(name="gatbox-01", public_id="a" * 32, token_hash="x")
        db.session.add_all([widget, gadget, device])
        db.session.commit()
        reading = RailSession(uid="1" * 32, device_id=device.id, game_id=widget.id,
                              file="rail_20261001_010101.csv", verdict="fail")
        db.session.add(reading)
        db.session.commit()
        open_ = MaintenanceRecord(game_id=widget.id, issue_description="Rail sags under load",
                                  status="Open")
        closed = MaintenanceRecord(game_id=widget.id, issue_description="Old fix",
                                   status="Completed")
        other = MaintenanceRecord(game_id=gadget.id, issue_description="Not this machine",
                                  status="Open")
        db.session.add_all([open_, closed, other])
        db.session.commit()
        return {"uid": reading.uid, "session": reading.id, "widget": widget.id,
                "gadget": gadget.id, "open": open_.id, "closed": closed.id,
                "other": other.id}


def tags(order_id):
    from app.models import RailSessionTag

    return RailSessionTag.query.filter_by(maintenance_record_id=order_id).all()


def attach(client, bench, order, note=""):
    return client.post(f"/rails/session/{bench['uid']}/attach",
                       data={"order": str(order), "note": note})


def test_the_page_offers_only_this_machines_open_orders(operator, bench):
    body = operator.get(f"/rails/session/{bench['uid']}").get_data(as_text=True)
    assert f'<option value="{bench["open"]}">' in body
    assert f'<option value="{bench["closed"]}">' not in body
    assert f'<option value="{bench["other"]}">' not in body
    assert f"/maintenance/game/{bench['widget']}?rail_session={bench['uid']}" in body


def test_attach_adds_the_reading_to_the_order(app, operator, bench):
    resp = attach(operator, bench, bench["open"], note="after the rectifier")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/maintenance_detail/{bench['open']}")
    [tag] = tags(bench["open"])
    assert tag.rail_session_id == bench["session"]
    assert tag.note == "after the rectifier"
    assert tag.source == "web"


def test_an_attached_order_is_listed_and_no_longer_offered(operator, bench):
    attach(operator, bench, bench["open"])
    body = operator.get(f"/rails/session/{bench['uid']}").get_data(as_text=True)
    assert "reading attached" in body
    assert f'<option value="{bench["open"]}">' not in body


def test_attaching_twice_keeps_one_tag(operator, bench):
    attach(operator, bench, bench["open"])
    attach(operator, bench, bench["open"])
    assert len(tags(bench["open"])) == 1


@pytest.mark.parametrize("which", ["closed", "other"])
def test_closed_orders_and_other_machines_are_refused(operator, bench, which):
    resp = attach(operator, bench, bench[which])
    assert resp.headers["Location"].endswith(f"/rails/session/{bench['uid']}")
    assert tags(bench[which]) == []


@pytest.mark.parametrize("order", ["", "abc", "999999"])
def test_a_missing_order_is_refused(operator, bench, order):
    resp = attach(operator, bench, order)
    assert resp.headers["Location"].endswith(f"/rails/session/{bench['uid']}")


def test_an_overlong_note_is_refused(operator, bench):
    attach(operator, bench, bench["open"], note="x" * 2001)
    assert tags(bench["open"]) == []


def test_read_only_users_cannot_attach(app, client, bench):
    sign_in(app, client, "readonly")
    body = client.get(f"/rails/session/{bench['uid']}").get_data(as_text=True)
    assert "Add to order" not in body
    attach(client, bench, bench["open"])
    assert tags(bench["open"]) == []


def new_order(client, game_id, uid):
    return client.post(f"/maintenance/game/{game_id}", data={
        "issue_description": "Rail low at idle", "status": "Open", "priority": "Medium",
        "machine_down": "no", "rail_session": uid})


def newest(game_id):
    from app.models import MaintenanceRecord

    return (MaintenanceRecord.query.filter_by(game_id=game_id)
            .order_by(MaintenanceRecord.id.desc()).first())


def test_the_new_order_form_says_which_reading_it_links(operator, bench):
    body = operator.get(f"/maintenance/game/{bench['widget']}?rail_session={bench['uid']}"
                        ).get_data(as_text=True)
    assert "Linked to rail reading rail_20261001_010101.csv" in body
    assert f'name="rail_session" value="{bench["uid"]}"' in body


def test_a_new_order_records_the_reading_that_prompted_it(operator, bench):
    new_order(operator, bench["widget"], bench["uid"])
    assert newest(bench["widget"]).rail_session_id == bench["session"]


def test_another_machines_reading_is_not_linked(operator, bench):
    body = operator.get(f"/maintenance/game/{bench['gadget']}?rail_session={bench['uid']}"
                        ).get_data(as_text=True)
    assert "Linked to rail reading" not in body
    new_order(operator, bench["gadget"], bench["uid"])
    order = newest(bench["gadget"])
    assert order.issue_description == "Rail low at idle"
    assert order.rail_session_id is None
