"""The v1 machine API: GATBOX pushes here, this application never calls out.

The wire format is `contract/v1/README.md`, and the examples under `contract/v1/examples/`
are its normative description -- `tests/test_api_v1_contract.py` posts them and compares the
replies byte-for-byte, so this code and that documentation cannot drift apart.

Three things about this blueprint differ deliberately from the rest of the application:

* **No `@login_required`, ever.** `login_manager.login_view` is set and there is no
  `unauthorized_handler`, so that decorator answers an unauthenticated caller with a 302 to
  an HTML login form. A machine client needs a 401 and JSON. `requires_device` is the check.
* **CSRF-exempt explicitly.** `WTF_CSRF_CHECK_DEFAULT` is already False, so these routes are
  unchecked today whatever we do; saying so means they keep working if that default is ever
  tightened, instead of failing mysteriously.
* **Rate limited before authentication.** The limit decorator sits outside
  `requires_device` on purpose: verifying a token runs scrypt, which is deliberately slow,
  so an unauthenticated flood would otherwise be a CPU exhaustion attack.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from app.extensions import csrf, db, limiter
from app.models import Game, MaintenanceRecord, RailSession, Reading
from app.utils.decorators import device_rate_key, requires_device

api_v1_bp = Blueprint("api_v1", __name__, url_prefix="/api/v1")
csrf.exempt(api_v1_bp)

CONTRACT = "v1"

# Contract limits. Over any of them is a 400 that writes nothing, never a partial accept.
MAX_ITEMS = 100
MAX_READINGS_PER_SESSION = 2000
MAX_READINGS_PER_REQUEST = 20000

UID = re.compile(r"^[0-9a-f]{32}$")
OPEN_STATUSES = ("Open", "In_Progress")
VERDICTS = ("held", "left", "over")


# ============================================================================
# HELPERS
# ============================================================================

def _bad(message: str, code: int = 400):
    return jsonify({"error": message}), code


def _when(value):
    """An epoch float from the wire to a naive-UTC datetime, or None.

    Epoch is authoritative in the contract because the Pi's CSV timestamps are local wall
    clock with no offset, which means nothing on another host.

    **Naive on purpose.** These columns are TIMESTAMP WITHOUT TIME ZONE, and handing psycopg2
    an aware datetime makes it convert to the database session's own zone and drop the
    offset: 09:00 UTC is stored as 04:00 on a server set to CDT, and every page then labels
    that "UTC". Worse, it is silently right on a UTC server and wrong on any other, so the
    same code stores a different instant depending on a setting nothing here can see.
    Converting to UTC and dropping the tzinfo ourselves stores the instant we were sent,
    whatever the server is set to -- and matches what rails._epoch assumes on the way out.
    """
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), timezone.utc).replace(tzinfo=None)
    return None


def _number(value):
    return float(value) if isinstance(value, (int, float)) else None


def _games_by_slug(slugs):
    """One query for every machine an ingest mentions, rather than one per item."""
    wanted = {s for s in slugs if isinstance(s, str) and s}
    if not wanted:
        return {}
    rows = Game.query.filter(Game.barcode.in_(wanted)).all()
    return {row.barcode: row for row in rows}


# ============================================================================
# API ROUTES
# ============================================================================

@api_v1_bp.route("/health", methods=["GET"])
def health():
    """Reachability, with no token.

    Open on purpose: GATBOX uses this to choose between the LAN address and the tunnel,
    and it needs that answer before it commits to sending anything. It reveals only that
    the application is up, which an unauthenticated request to `/` reveals anyway.
    """
    return jsonify({"ok": True, "contract": CONTRACT, "time": time.time()})


@api_v1_bp.route("/ingest", methods=["POST"])
@limiter.limit("120 per minute", key_func=device_rate_key)
@requires_device
def ingest():
    """Accept rail sessions and maintenance orders, and say what happened to each."""
    device = g.device
    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return _bad("body must be a JSON object")
    if body.get("contract") != CONTRACT:
        return _bad(f"contract must be {CONTRACT!r}")
    # The uids in the payload are hashed with the device's public id, so a payload built
    # for another device carries ids this one could never reproduce. Refusing is cheaper
    # than storing rows nobody can match again.
    if body.get("device") != device.public_id:
        return _bad("the payload names a different device than the token does")

    items = body.get("items")
    if not isinstance(items, list) or not items:
        return _bad("items must be a non-empty list")
    if len(items) > MAX_ITEMS:
        return _bad(f"at most {MAX_ITEMS} items per request, got {len(items)}")

    total_readings = sum(
        len(item.get("readings") or [])
        for item in items
        if isinstance(item, dict) and isinstance(item.get("readings"), list)
    )
    if total_readings > MAX_READINGS_PER_REQUEST:
        return _bad(
            f"at most {MAX_READINGS_PER_REQUEST} readings per request, got {total_readings}"
        )

    games = _games_by_slug(
        item.get("machine") for item in items if isinstance(item, dict)
    )

    results = []
    try:
        for item in items:
            if not isinstance(item, dict):
                results.append({"uid": None, "kind": None, "status": "rejected",
                                "reason": "item must be a JSON object"})
                continue
            kind = item.get("kind")
            if kind == "rail_session":
                results.append(_ingest_session(device, item, games))
            elif kind == "order":
                results.append(_ingest_order(item, games))
            else:
                results.append({"uid": item.get("uid"), "kind": kind, "status": "rejected",
                                "reason": f"unknown kind {kind!r}"})
        device.last_seen = datetime.now(timezone.utc).replace(tzinfo=None)
        from app.security.utils import get_client_ip

        device.last_ip = get_client_ip()
        db.session.commit()
    except Exception:
        # Nothing half-written: the next attempt is a clean retry, which the deterministic
        # uids make safe.
        db.session.rollback()
        raise

    return jsonify({"contract": CONTRACT, "received": len(items), "results": results})


def _ingest_session(device, item, games):
    """Store one metered session and its trace. Statistics are taken as given."""
    uid = item.get("uid")
    out = {"uid": uid, "kind": "rail_session"}

    def rejected(reason):
        return {**out, "status": "rejected", "reason": reason}

    if not isinstance(uid, str) or not UID.match(uid):
        return rejected("uid must be 32 lowercase hex characters")
    file_name = item.get("file")
    if not isinstance(file_name, str) or not file_name:
        return rejected("file is required")

    readings = item.get("readings")
    if readings is None:
        readings = []
    if not isinstance(readings, list):
        return rejected("readings must be a list")
    if len(readings) > MAX_READINGS_PER_SESSION:
        return rejected(
            f"at most {MAX_READINGS_PER_SESSION} readings per session, got {len(readings)}"
        )

    slug = item.get("machine")
    game = games.get(slug)
    if game is None:
        # Never invent a machine. An unknown slug means the two sides disagree about the
        # floor, and the fix is a roster import, not a row conjured here.
        return rejected(f"no machine with slug {slug!r}")

    verdict = (item.get("verdict") or {})
    state = verdict.get("state")
    if state is not None and state not in VERDICTS:
        return rejected(f"verdict.state must be one of {', '.join(VERDICTS)} or null")

    session = RailSession.query.filter_by(uid=uid).first()
    status = "duplicate" if session is not None else "created"

    if session is None:
        window = item.get("window") or {}
        powered = item.get("powered") or {}
        profile = item.get("profile") or {}
        counts = item.get("counts") or {}
        clock = item.get("clock") or {}
        session = RailSession(
            uid=uid,
            device_id=device.id,
            game_id=game.id,
            file=file_name,
            started=_when(item.get("started")),
            ended=_when(item.get("ended")),
            duration_s=_number(item.get("duration_s")),
            samples=item.get("samples") if isinstance(item.get("samples"), int) else None,
            rate=_number(item.get("rate")),
            timebase=item.get("timebase"),
            clock=clock.get("source"),
            clock_ntp_from=_when(clock.get("ntp_from")),
            profile_id=profile.get("id"),
            profile_label=profile.get("label"),
            profile_kind=profile.get("kind"),
            rail=profile.get("rail"),
            mode=item.get("mode"),
            window_lo=_number(window.get("lo")),
            window_hi=_number(window.get("hi")),
            window_unit=window.get("unit"),
            window_source=window.get("source"),
            alarm_hi=_number(item.get("alarm_hi")),
            powered_mean=_number(powered.get("mean")),
            powered_min=_number(powered.get("min")),
            powered_max=_number(powered.get("max")),
            powered_readings=powered.get("readings")
            if isinstance(powered.get("readings"), int) else None,
            in_window_pct=_number(powered.get("in_window_pct")),
            verdict=state,
            verdict_detail=verdict.get("detail"),
            over_voltage=counts.get("over_voltage") or 0,
            excursions=counts.get("excursions") or 0,
            power_cycles=counts.get("power_cycles") or 0,
            gaps=counts.get("gaps") or 0,
            ol_events=counts.get("ol_events") or 0,
            marks=counts.get("marks") or 0,
            suspect=counts.get("suspect") or 0,
        )
        db.session.add(session)
        db.session.flush()        # we need session.id for the readings

    # Readings are reconciled even for a duplicate session. A first attempt that failed
    # part-way leaves the session row with some of its trace, and reporting "all duplicate"
    # without looking would be a comfortable lie. The uid lookup is one query either way.
    created, duplicate, bad = _ingest_readings(session, readings)
    if bad:
        return rejected(bad)

    return {**out, "status": status,
            "readings": {"created": created, "duplicate": duplicate}}


def _ingest_readings(session, readings):
    """Insert the trace points not already stored. Returns (created, duplicate, error)."""
    uids = []
    for reading in readings:
        if not isinstance(reading, dict):
            return 0, 0, "every reading must be a JSON object"
        uid = reading.get("uid")
        if not isinstance(uid, str) or not UID.match(uid):
            return 0, 0, "every reading needs a uid of 32 lowercase hex characters"
        if not isinstance(reading.get("epoch"), (int, float)):
            return 0, 0, f"reading {uid} has no numeric epoch"
        uids.append(uid)

    if not uids:
        return 0, 0, None

    # One query for the whole trace rather than two thousand.
    have = {
        row[0]
        for row in db.session.query(Reading.uid).filter(Reading.uid.in_(uids)).all()
    }
    created = 0
    for reading in readings:
        if reading["uid"] in have:
            continue
        db.session.add(
            Reading(
                uid=reading["uid"],
                rail_session_id=session.id,
                epoch=float(reading["epoch"]),
                up=_number(reading.get("up")),
                v=_number(reading.get("v")),
                raw=reading.get("raw"),
                unit=reading.get("unit"),
                mode=reading.get("mode"),
                alarm=reading.get("alarm"),
                ol=bool(reading.get("ol")),
            )
        )
        have.add(reading["uid"])
        created += 1
    return created, len(uids) - created, None


def _ingest_order(item, games):
    """Store a maintenance order raised at the bench."""
    uid = item.get("uid")
    out = {"uid": uid, "kind": "order"}

    def rejected(reason):
        return {**out, "status": "rejected", "reason": reason}

    if not isinstance(uid, str) or not UID.match(uid):
        return rejected("uid must be 32 lowercase hex characters")
    issue = item.get("issue")
    if not isinstance(issue, str) or not issue.strip():
        return rejected("issue is required")

    slug = item.get("machine")
    game = games.get(slug)
    if game is None:
        return rejected(f"no machine with slug {slug!r}")

    if MaintenanceRecord.query.filter_by(external_id=uid).first() is not None:
        return {**out, "status": "duplicate"}

    session_uid = item.get("rail_session")
    session_id = None
    if session_uid:
        session = RailSession.query.filter_by(uid=session_uid).first()
        if session is None:
            # Send the session first. Refusing keeps the link rather than dropping it
            # silently, and the retry costs nothing because both items are idempotent.
            return rejected(f"rail_session {session_uid!r} has not been ingested yet")
        session_id = session.id

    db.session.add(
        MaintenanceRecord(
            game_id=game.id,
            issue_description=issue.strip(),
            priority=item.get("priority") or "Medium",
            technician=item.get("technician"),
            status="Open",
            work_order_type="game",
            date_reported=_when(item.get("created"))
            or datetime.now(timezone.utc).replace(tzinfo=None),
            external_id=uid,
            source="gatbox",
            rail_session_id=session_id,
        )
    )
    return {**out, "status": "created"}


@api_v1_bp.route("/roster", methods=["GET"])
@limiter.limit("60 per minute", key_func=device_rate_key)
@requires_device
def roster():
    """The machines this hub knows, so GATBOX can tell which slugs will be accepted.

    Only machines with an identifier appear: one without a barcode cannot be the subject of
    an ingest, so offering it would promise something that would be rejected.
    """
    machines = (
        Game.query.filter(Game.barcode.isnot(None)).order_by(Game.name).all()
    )
    return jsonify({
        "contract": CONTRACT,
        "machines": [
            {"slug": m.barcode, "name": m.name, "status": m.status,
             "location": m.location}
            for m in machines
        ],
    })


@api_v1_bp.route("/machines/<slug>/orders", methods=["GET"])
@limiter.limit("60 per minute", key_func=device_rate_key)
@requires_device
def machine_orders(slug):
    """A machine's maintenance orders, so the bench can see what is already reported."""
    wanted = request.args.get("status", "open").lower()
    if wanted not in ("open", "all"):
        return _bad("status must be 'open' or 'all'")

    game = Game.query.filter_by(barcode=slug).first()
    if game is None:
        return _bad(f"no machine with slug {slug!r}", 404)

    query = MaintenanceRecord.query.filter_by(game_id=game.id)
    if wanted == "open":
        query = query.filter(MaintenanceRecord.status.in_(OPEN_STATUSES))
    orders = query.order_by(MaintenanceRecord.date_reported.desc()).all()

    return jsonify({
        "contract": CONTRACT,
        "machine": slug,
        "status": wanted,
        "orders": [
            {
                "id": o.id,
                "external_id": o.external_id,
                "issue": o.issue_description,
                "priority": o.priority,
                "status": o.status,
                "source": o.source,
                "reported": o.date_reported.replace(tzinfo=timezone.utc).timestamp()
                if o.date_reported else None,
            }
            for o in orders
        ],
    })
