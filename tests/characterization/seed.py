"""The synthetic arcade: three machines, four users, parts, orders and one rail session."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from werkzeug.security import generate_password_hash

from char_support import PASSWORD, ROLES


def _dt(days_ago: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=days_ago)


def seed_floor() -> dict:
    """Build the synthetic arcade in the current app context; return a dict of ids.

    Shared by the characterization tests and ``tests/screenshots/take.py``. Every name in it is
    invented: the repository is public.
    """
    from app.extensions import db
    from app.models import (
        Device, Game, InventoryItem, InventoryRequest, InventoryRequestHistory, LowStockAlert,
        MaintenanceRecord, PlayRecord, RailSession, Reading, StockHistory, User, WorkLog,
    )

    users = {}
    for role in ROLES:
        u = User(username=f"test-{role}", role=role, is_active=True, must_change_password=False)
        # A deliberately cheap hash: the suite logs in a few hundred times, and the default
        # scrypt cost is most of its run time. check_password accepts any method.
        u.password_hash = generate_password_hash(PASSWORD, method="pbkdf2:sha256:1000")
        db.session.add(u)
        users[role] = u

    raider = Game(name="Neon Raider", barcode="neon-raider", manufacturer="Synthwave Co",
                  year=1987, genre="Shooter", location="Floor", status="Working",
                  counter_status="Working", coins_per_play=0.5, total_plays=40,
                  total_revenue=20.0, date_added=_dt(60))
    pinball = Game(name="Pixel Pinball", barcode="pixel-pinball", manufacturer="Flipper Labs",
                   location="Warehouse", status="Not_Working", counter_status="Working",
                   coins_per_play=1.0, date_added=_dt(30))
    courier = Game(name="Star Courier", barcode="star-courier", location="Floor",
                   status="Working", counter_status="Broken_Counter", coins_per_play=0.25,
                   total_plays=5, total_revenue=1.25, date_added=_dt(10))
    db.session.add_all([raider, pinball, courier])
    db.session.flush()

    db.session.add_all([
        PlayRecord(game_id=raider.id, coin_count=100, plays_count=0, revenue=0.0,
                   date_recorded=date.today() - timedelta(days=20), notes="Baseline"),
        PlayRecord(game_id=raider.id, coin_count=140, plays_count=40, revenue=20.0,
                   date_recorded=date.today() - timedelta(days=5), notes="Weekly read"),
    ])

    belt = InventoryItem(name="Drive Belt", description="Synthetic belt", stock_quantity=10,
                         unit_price=4.0, minimum_stock=2, supplier="Parts Depot",
                         part_number="BELT-01")
    fuse = InventoryItem(name="Glass Fuse 2A", stock_quantity=1, unit_price=0.5,
                         minimum_stock=5, part_number="FUSE-2A")
    db.session.add_all([belt, fuse])
    db.session.flush()
    alert = LowStockAlert(item_id=fuse.id, email_sent=False)
    db.session.add(alert)
    db.session.add(StockHistory(item_id=belt.id, change_type="added", quantity_change=10,
                                previous_quantity=0, new_quantity=10, reason="Initial stock",
                                user_id=users["manager"].id))

    open_order = MaintenanceRecord(game_id=raider.id, issue_description="Joystick drifts left",
                                   technician="Tech A", status="Open", priority="High",
                                   date_reported=_dt(3))
    closed_order = MaintenanceRecord(game_id=raider.id, issue_description="Coin mech jammed",
                                     fix_description="Cleared the chute", cost=12.5,
                                     technician="Tech B", status="Fixed",
                                     date_reported=_dt(9), date_fixed=_dt(8))
    general = MaintenanceRecord(game_id=None, work_order_type="facility",
                                location_description="Back bar", status="Open",
                                issue_description="Ceiling light flickers", date_reported=_dt(1))
    db.session.add_all([open_order, closed_order, general])
    db.session.flush()
    db.session.add(WorkLog(maintenance_id=open_order.id, user_id=users["operator"].id,
                           work_description="Reseated the harness", time_spent=0.5))

    req = InventoryRequest(item_id=belt.id, item_name="Drive Belt", quantity_requested=3,
                           reason="Spare stock", urgency="Normal", status="Pending",
                           requested_by_id=users["operator"].id)
    db.session.add(req)
    db.session.flush()
    db.session.add(InventoryRequestHistory(request_id=req.id, user_id=users["operator"].id,
                                           action="created", notes="Request created"))

    device = Device(name="bench-test")
    device.public_id = "c" * 12
    device.issue_token()
    db.session.add(device)
    db.session.flush()
    session = RailSession(uid="d" * 32, device_id=device.id, game_id=raider.id,
                          file="rail_20260901_010000.csv", started=_dt(2), ended=_dt(2),
                          duration_s=6.0, samples=2, rail="+5V", mode="VDC",
                          window_lo=4.75, window_hi=5.25, window_unit="V",
                          window_source="profile", powered_mean=5.01, powered_min=4.99,
                          powered_max=5.03, powered_readings=2, in_window_pct=100.0,
                          verdict="held",
                          verdict_detail="held detail")
    db.session.add(session)
    db.session.flush()
    for i, v in enumerate((5.0, 5.02)):
        db.session.add(Reading(uid=f"{i:032x}", rail_session_id=session.id,
                               epoch=1790000000.0 + i, v=v, raw=f"{v:.3f}", unit="V",
                               mode="VDC", ol=False))
    db.session.commit()

    return {
        "users": {role: u.id for role, u in users.items()},
        "raider": raider.id, "pinball": pinball.id, "courier": courier.id,
        "belt": belt.id, "fuse": fuse.id, "alert": alert.id,
        "open_order": open_order.id, "closed_order": closed_order.id, "general": general.id,
        "request": req.id, "session_uid": session.uid,
    }
