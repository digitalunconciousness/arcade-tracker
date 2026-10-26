"""The device allow-list and the per-item text limits on /api/v1 (2026-10-26).

Owner's decisions: existing devices keep every machine; a limited device sees only its
machines and anything else it sends is rejected; machines are chosen on Admin, Devices; text
over a limit rejects the item, not the request. Additive: an unrestricted device behaves as the
contract always said (tests/test_api_v1_contract.py still posts the examples unchanged).
"""
from __future__ import annotations

import copy
import os
import sys

import pytest
from test_api_v1_contract import auth, example

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def bench(app):
    """The contract tests' device: the public id the example payload was made for, and the
    two machines it names."""
    from app.extensions import db
    from app.models import Device, Game

    dev = Device(name="test-bench")
    dev.public_id = "a1b2c3d4e5f6"
    token = dev.issue_token()
    db.session.add_all([dev, Game(name="Widget Wars", barcode="widget-wars", status="Working",
                                  location="Floor"),
                        Game(name="Sprocket", barcode="pin-sprocket", status="Working",
                             location="Floor")])
    db.session.commit()
    return {"token": token, "public_id": dev.public_id, "name": dev.name}


def limit_to(app, *slugs):
    from app.extensions import db
    from app.models import Device, Game

    dev = Device.query.filter_by(name="test-bench").one()
    dev.all_machines = False
    dev.machines = Game.query.filter(Game.barcode.in_(slugs)).all()
    db.session.commit()


def ingest(client, bench, payload):
    return client.post("/api/v1/ingest", json=payload, headers=auth(bench))


def statuses(resp):
    return [(r["kind"], r["status"], r.get("reason")) for r in resp.get_json()["results"]]


# --- the default changes nothing -----------------------------------------------------------------

def test_a_device_made_before_the_list_may_use_every_machine(app, bench):
    from app.models import Device

    assert Device.query.filter_by(name="test-bench").one().all_machines is True


# --- a limited device ----------------------------------------------------------------------------

def test_items_for_a_machine_off_the_list_are_rejected(client, app, bench):
    from app.models import MaintenanceRecord, RailSession

    limit_to(app, "pin-sprocket")
    resp = ingest(client, bench, example("ingest-request.json"))
    assert resp.status_code == 200
    reason = "machine 'widget-wars' is not on this device's list"
    assert statuses(resp) == [("rail_session", "rejected", reason), ("order", "rejected", reason)]
    assert RailSession.query.count() == 0 and MaintenanceRecord.query.count() == 0


def test_items_for_its_own_machines_go_through(client, app, bench):
    limit_to(app, "widget-wars")
    resp = ingest(client, bench, example("ingest-request.json"))
    assert [s for _, s, _ in statuses(resp)] == ["created", "created"]


def test_it_sees_only_its_machines(client, app, bench):
    limit_to(app, "pin-sprocket")
    slugs = [m["slug"] for m in client.get("/api/v1/roster",
                                           headers=auth(bench)).get_json()["machines"]]
    assert slugs == ["pin-sprocket"]


def test_another_machines_orders_look_like_an_unknown_machine(client, app, bench):
    limit_to(app, "pin-sprocket")
    other = client.get("/api/v1/machines/widget-wars/orders", headers=auth(bench))
    unknown = client.get("/api/v1/machines/no-such-machine/orders", headers=auth(bench))
    assert (other.status_code, unknown.status_code) == (404, 404)
    assert other.get_json()["error"].replace("widget-wars", "X") == \
        unknown.get_json()["error"].replace("no-such-machine", "X")
    assert client.get("/api/v1/machines/pin-sprocket/orders",
                      headers=auth(bench)).status_code == 200


def test_it_can_tag_only_its_machines_orders(client, app, bench):
    from app.extensions import db
    from app.models import MaintenanceRecord

    ingest(client, bench, example("ingest-request.json"))       # session + order, all allowed
    session_uid = example("ingest-request.json")["items"][0]["uid"]
    order = MaintenanceRecord.query.filter_by(source="gatbox").one()
    general = MaintenanceRecord(issue_description="Bar light", work_order_type="general")
    db.session.add(general)
    db.session.commit()

    def tag(order_id, uid_char):
        return statuses(ingest(client, bench, {"contract": "v1", "device": "a1b2c3d4e5f6",
                                                "items": [{"kind": "session_tag",
                                                           "uid": uid_char * 32,
                                                           "order": order_id,
                                                           "rail_session": session_uid}]}))

    limit_to(app, "pin-sprocket")
    assert tag(order.id, "a")[0][1:] == ("rejected",
                                         "that order isn't for one of this device's machines")
    assert tag(general.id, "b")[0][1] == "rejected", "a general order is no machine's"


# --- text limits --------------------------------------------------------------------------------

@pytest.mark.parametrize(("index", "field", "value", "reason"), [
    (1, "issue", "x" * 2001, "issue is at most 2000 characters"),
    (1, "technician", "x" * 51, "technician is text of at most 50 characters"),
    (1, "technician", 12, "technician is text of at most 50 characters"),
    (0, "file", "x" * 65, "file is at most 64 characters"),
])
def test_text_over_a_limit_rejects_the_item_not_the_request(client, bench, index, field,
                                                           value, reason):
    payload = copy.deepcopy(example("ingest-request.json"))
    payload["items"][index][field] = value
    resp = ingest(client, bench, payload)
    assert resp.status_code == 200
    results = statuses(resp)
    assert results[index][1:] == ("rejected", reason)


def test_text_at_the_limit_is_fine(client, bench):
    payload = copy.deepcopy(example("ingest-request.json"))
    payload["items"][1]["issue"] = "x" * 2000
    payload["items"][1]["technician"] = "x" * 50
    assert [s for _, s, _ in statuses(ingest(client, bench, payload))] == ["created", "created"]


def test_an_over_long_note_on_a_tag_is_rejected(client, bench):
    from app.models import MaintenanceRecord

    ingest(client, bench, example("ingest-request.json"))
    order = MaintenanceRecord.query.filter_by(source="gatbox").one()
    resp = ingest(client, bench, {"contract": "v1", "device": "a1b2c3d4e5f6", "items": [{
        "kind": "session_tag", "uid": "c" * 32, "order": order.id,
        "rail_session": example("ingest-request.json")["items"][0]["uid"], "note": "x" * 2001}]})
    assert statuses(resp)[0][1:] == ("rejected", "note is text of at most 2000 characters")


# --- Admin, Devices -----------------------------------------------------------------------------

def test_an_admin_limits_a_device_and_it_is_logged(client, app, bench, caplog):
    from char_support import login
    from seed import seed_floor

    from app.extensions import db
    from app.models import Device, Game

    seed_floor()
    login(client, "admin")
    dev = Device.query.filter_by(name="test-bench").one()
    sprocket = Game.query.filter_by(barcode="pin-sprocket").one()
    resp = client.post(f"/admin/devices/{dev.id}", data={
        "scope": "list", "machines": [str(sprocket.id)], "enabled": "1"})
    assert resp.status_code == 302
    db.session.expire_all()
    dev = db.session.get(Device, dev.id)
    assert (dev.all_machines, [m.barcode for m in dev.machines], dev.enabled) == (
        False, ["pin-sprocket"], True)
    assert "DEVICE_SCOPE_CHANGED" in caplog.text


def test_an_empty_list_is_refused(client, app, bench):
    from char_support import login
    from seed import seed_floor

    from app.models import Device

    seed_floor()
    login(client, "admin")
    dev = Device.query.filter_by(name="test-bench").one()
    resp = client.post(f"/admin/devices/{dev.id}", data={"scope": "list", "enabled": "1"})
    assert resp.status_code == 400 and "Tick at least one machine" in resp.get_data(as_text=True)
    assert Device.query.filter_by(name="test-bench").one().all_machines is True


def test_turning_a_device_off_refuses_its_requests(client, app, bench):
    from char_support import login
    from seed import seed_floor

    from app.models import Device

    seed_floor()
    login(client, "admin")
    dev = Device.query.filter_by(name="test-bench").one()
    client.post(f"/admin/devices/{dev.id}", data={"scope": "all"})
    assert client.get("/api/v1/roster", headers=auth(bench)).status_code == 401


# --- the migration ------------------------------------------------------------------------------

def test_the_migration_round_trips_and_existing_devices_keep_every_machine(app, bench):
    import sqlalchemy as sa
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    def migrate(step, revision):
        db.session.commit()
        step(directory=os.path.join(ROOT, "migrations"), revision=revision)

    inspect = sa.inspect
    stamp(directory=os.path.join(ROOT, "migrations"), revision="c8d9e0f1a2b3")
    migrate(downgrade, "b6c7d8e9f0a1")
    assert not inspect(db.engine).has_table("device_machine")
    migrate(upgrade, "c8d9e0f1a2b3")
    migrate(upgrade, "c8d9e0f1a2b3")
    assert inspect(db.engine).has_table("device_machine")
    assert db.session.execute(sa.text("SELECT all_machines FROM device")).scalar() in (1, True)
