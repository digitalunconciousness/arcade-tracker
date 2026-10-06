"""``RailSessionTag``: a trace attached to a work order after the fact.

Phase 6. A machine already has an order open and someone meters it again at the bench. The
second trace belongs on the order that exists, not on a duplicate order nobody asked for.

``maintenance_record.rail_session_id`` is a single FK and stays what it is -- *the session
that prompted this order*, which is in contract v1 and carries real information. This table is
the set of traces attached afterwards. The two are kept apart rather than merged, because a
copy of the prompting session in both places is a thing that can drift.

Every machine and session in these tests is invented.
"""
from __future__ import annotations

import pytest


@pytest.fixture()
def bench(app):
    """A machine, a device, two sessions and one open order prompted by the first session."""
    from app.extensions import db
    from app.models import Device, Game, MaintenanceRecord, RailSession

    with app.app_context():
        game = Game(name="Widget Wars", barcode="widget-wars")
        device = Device(name="gatbox-01", public_id="a" * 32, token_hash="x")
        db.session.add_all([game, device])
        db.session.commit()
        first = RailSession(uid="1" * 32, device_id=device.id, game_id=game.id,
                            file="rail_20261006_010101.csv")
        second = RailSession(uid="2" * 32, device_id=device.id, game_id=game.id,
                             file="rail_20261006_020202.csv")
        db.session.add_all([first, second])
        db.session.commit()
        order = MaintenanceRecord(game_id=game.id, issue_description="Rail sags under load",
                                  status="Open", source="gatbox", external_id="o" * 32,
                                  rail_session_id=first.id)
        db.session.add(order)
        db.session.commit()
        return {"game": game.id, "order": order.id,
                "first": first.id, "second": second.id}


def test_an_order_can_carry_a_second_trace(app, bench):
    from app.extensions import db
    from app.models import MaintenanceRecord, RailSessionTag

    with app.app_context():
        db.session.add(RailSessionTag(maintenance_record_id=bench["order"],
                                      rail_session_id=bench["second"]))
        db.session.commit()
        order = db.session.get(MaintenanceRecord, bench["order"])
        assert [t.rail_session_id for t in order.session_tags] == [bench["second"]]


def test_an_order_can_carry_several(app, bench):
    from app.extensions import db
    from app.models import MaintenanceRecord, RailSessionTag

    with app.app_context():
        db.session.add_all([
            RailSessionTag(maintenance_record_id=bench["order"],
                           rail_session_id=bench["first"]),
            RailSessionTag(maintenance_record_id=bench["order"],
                           rail_session_id=bench["second"]),
        ])
        db.session.commit()
        order = db.session.get(MaintenanceRecord, bench["order"])
        assert len(order.session_tags) == 2


def test_the_same_pair_twice_is_refused(app, bench):
    """Idempotency at the database, not only in the ingest path: the same tag sent twice must
    not become two rows however it arrives."""
    import sqlalchemy.exc
    from app.extensions import db
    from app.models import RailSessionTag

    with app.app_context():
        db.session.add(RailSessionTag(maintenance_record_id=bench["order"],
                                      rail_session_id=bench["second"]))
        db.session.commit()
        db.session.add(RailSessionTag(maintenance_record_id=bench["order"],
                                      rail_session_id=bench["second"]))
        with pytest.raises(sqlalchemy.exc.IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_the_same_session_can_be_tagged_to_two_orders(app, bench):
    """One trace can be evidence for two different faults."""
    from app.extensions import db
    from app.models import MaintenanceRecord, RailSessionTag

    with app.app_context():
        other = MaintenanceRecord(game_id=bench["game"], issue_description="Coin door sticks",
                                  status="Open", source="web")
        db.session.add(other)
        db.session.commit()
        db.session.add_all([
            RailSessionTag(maintenance_record_id=bench["order"],
                           rail_session_id=bench["second"]),
            RailSessionTag(maintenance_record_id=other.id,
                           rail_session_id=bench["second"]),
        ])
        db.session.commit()
        assert RailSessionTag.query.count() == 2


def test_deleting_the_order_takes_its_tags(app, bench):
    from app.extensions import db
    from app.models import MaintenanceRecord, RailSessionTag

    with app.app_context():
        db.session.add(RailSessionTag(maintenance_record_id=bench["order"],
                                      rail_session_id=bench["second"]))
        db.session.commit()
        db.session.delete(db.session.get(MaintenanceRecord, bench["order"]))
        db.session.commit()
        assert RailSessionTag.query.count() == 0


def test_deleting_the_order_leaves_the_session(app, bench):
    """A trace is the device's record of what it measured, not a property of the order that
    cited it -- the same reason a session survives its machine being deleted."""
    from app.extensions import db
    from app.models import MaintenanceRecord, RailSession, RailSessionTag

    with app.app_context():
        db.session.add(RailSessionTag(maintenance_record_id=bench["order"],
                                      rail_session_id=bench["second"]))
        db.session.commit()
        db.session.delete(db.session.get(MaintenanceRecord, bench["order"]))
        db.session.commit()
        assert db.session.get(RailSession, bench["second"]) is not None


def test_tagging_does_not_disturb_the_prompting_session(app, bench):
    """The two mean different things and the order page labels them differently."""
    from app.extensions import db
    from app.models import MaintenanceRecord, RailSessionTag

    with app.app_context():
        db.session.add(RailSessionTag(maintenance_record_id=bench["order"],
                                      rail_session_id=bench["second"]))
        db.session.commit()
        order = db.session.get(MaintenanceRecord, bench["order"])
        assert order.rail_session_id == bench["first"]


def test_a_tag_can_carry_a_note_and_a_source(app, bench):
    from app.extensions import db
    from app.models import MaintenanceRecord, RailSessionTag

    with app.app_context():
        db.session.add(RailSessionTag(maintenance_record_id=bench["order"],
                                      rail_session_id=bench["second"],
                                      note="second pass, cold", source="gatbox"))
        db.session.commit()
        tag = db.session.get(MaintenanceRecord, bench["order"]).session_tags[0]
        assert tag.note == "second pass, cold"
        assert tag.source == "gatbox"
        assert tag.created is not None and tag.created.tzinfo is None
