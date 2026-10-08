"""The rail-history views: the floor, one machine, one session.

These seed sessions directly rather than going through the API, so they are fast and
deterministic and do not need GATBOX. The whole pipe — GATBOX to hub to a rendered page — is
covered by gdd-integration/verify-sync.sh, which needs both repositories.

Every machine here is invented.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

import pytest


def _dt(day, hour=12):
    return datetime(2026, 9, day, hour, 0, 0, tzinfo=timezone.utc)


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
def floor(app):
    """A machine with three sessions, and a second machine with none.

    The three are deliberately varied: one held, one left the window, one over-voltage; the
    third also has a *different* window, which is what exercises the stepped band.
    """
    from app.extensions import db
    from app.models import Device, Game, RailSession, Reading

    with app.app_context():
        device = Device(name="bench")
        device.public_id = "aaaaaaaaaaaa"
        device.issue_token()
        widget = Game(name="Widget Wars", barcode="widget-wars", status="Working")
        quiet = Game(name="Quiet Cabinet", barcode="quiet-cabinet", status="Working")
        db.session.add_all([device, widget, quiet])
        db.session.commit()

        made = []
        spec = [
            ("held", 5.01, 4.75, 5.25, 5.775, 0, 0, "ntp"),
            ("left", 5.30, 4.75, 5.25, 5.775, 0, 2, "ntp"),
            # A tighter window, so the history has two distinct window values.
            ("over", 6.10, 4.90, 5.10, 5.610, 1, 1, "unverified"),
        ]
        for n, (verdict, mean, lo, hi, alarm, ov, exc, clock) in enumerate(spec, start=20):
            s = RailSession(
                uid=f"{n:032x}", device_id=device.id, game_id=widget.id,
                file=f"rail_202609{n}_010000.csv",
                started=_dt(n), ended=_dt(n) + timedelta(seconds=6),
                duration_s=6.0, samples=4, rate=2.0, timebase="monotonic",
                clock=clock, clock_ntp_from=_dt(19) if clock != "ntp" else None,
                profile_id="rail-5v", profile_label="+5V rail", profile_kind="rail",
                rail="+5V", mode="VDC",
                window_lo=lo, window_hi=hi, window_unit="V", window_source="profile",
                alarm_hi=alarm,
                powered_mean=mean, powered_min=mean - 0.01, powered_max=mean + 0.01,
                powered_readings=3, in_window_pct=100.0 if verdict == "held" else 50.0,
                verdict=verdict, verdict_detail=f"{verdict} detail",
                over_voltage=ov, excursions=exc, power_cycles=1, suspect=0,
            )
            db.session.add(s)
            db.session.flush()
            # Four readings: three real, one over-range. The over-range one is the point --
            # it must reach the page as null, never as zero.
            for i, (v, raw, unit, alarm_state, ol) in enumerate([
                (mean, f"{mean:.3f}", "V", "ok", False),
                (mean, f"{mean:.3f}", "V", "ok", False),
                (mean + 1.1, f"{mean + 1.1:.3f}", "V", "spike", False),
                (None, "inf", "TΩ", None, True),
            ]):
                db.session.add(Reading(
                    uid=f"{n:030x}{i:02x}", rail_session_id=s.id,
                    epoch=1790000000.0 + i / 2, up=100.0 + i / 2,
                    v=v, raw=raw, unit=unit, mode="VDC", alarm=alarm_state, ol=ol,
                ))
            made.append(s.uid)
        db.session.commit()
        return {"uids": made, "widget": widget.id, "quiet": quiet.id}


def island(html, element_id):
    """The JSON island a page hands to Chart.js."""
    m = re.search(
        rf'<script type="application/json" id="{element_id}">(.*?)</script>',
        html, re.S)
    assert m, f"no JSON island {element_id!r} on the page"
    return json.loads(m.group(1))


# --- not open to the world --------------------------------------------------

@pytest.mark.parametrize("path", [
    "/rails/", "/rails/machine/widget-wars", "/rails/session/" + "0" * 32,
])
def test_every_view_needs_a_session(client, path):
    response = client.get(path, follow_redirects=False)
    assert response.status_code != 200
    assert "/login" in response.headers.get("Location", "")


# --- the floor --------------------------------------------------------------

def test_the_floor_lists_what_arrived(signed_in, floor):
    body = signed_in.get("/rails/").get_data(as_text=True)
    assert "Widget Wars" in body
    assert "over-voltage" in body and "held the window" in body


def test_the_floor_says_so_when_nothing_has_arrived(signed_in):
    body = signed_in.get("/rails/").get_data(as_text=True)
    assert "Nothing has arrived yet" in body
    assert "hub.conf" in body, "it should say what is missing, not just that it is empty"


# --- one machine ------------------------------------------------------------

def test_a_machine_is_addressed_by_its_slug(signed_in, floor):
    """The same identifier the cabinet label and GATBOX use."""
    assert signed_in.get("/rails/machine/widget-wars").status_code == 200
    assert signed_in.get("/rails/machine/no-such-machine").status_code == 404


def test_the_history_chart_carries_one_point_per_session(signed_in, floor):
    data = island(signed_in.get("/rails/machine/widget-wars").get_data(as_text=True),
                  "history-data")
    assert len(data["points"]) == 3
    assert [p["verdict"] for p in data["points"]] == ["held", "left", "over"]


def test_the_window_travels_per_point_so_a_change_can_step(signed_in, floor):
    """One flat band across the history would claim the window never moved. It did."""
    data = island(signed_in.get("/rails/machine/widget-wars").get_data(as_text=True),
                  "history-data")
    assert {p["lo"] for p in data["points"]} == {4.75, 4.90}
    assert {p["hi"] for p in data["points"]} == {5.25, 5.10}


def test_a_changed_window_is_called_out_in_words(signed_in, floor):
    body = signed_in.get("/rails/machine/widget-wars").get_data(as_text=True)
    assert "window changed during this history" in body


def test_each_verdict_gets_its_own_colour(signed_in, floor):
    data = island(signed_in.get("/rails/machine/widget-wars").get_data(as_text=True),
                  "history-data")
    colours = {p["verdict"]: p["colour"] for p in data["points"]}
    assert len(set(colours.values())) == 3, colours


def test_a_machine_with_no_sessions_renders(signed_in, floor):
    response = signed_in.get("/rails/machine/quiet-cabinet")
    assert response.status_code == 200
    assert "No sessions for this machine" in response.get_data(as_text=True)


def test_the_history_view_never_queries_readings(signed_in, floor):
    """RailSession.readings is lazy: touching it per session is a query per session, each
    pulling up to 2000 rows. This page has no use for a trace, so it must not load one."""
    from sqlalchemy import event

    from app.extensions import db

    seen = []

    def record(conn, cursor, statement, params, context, many):
        seen.append(statement)

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        assert signed_in.get("/rails/machine/widget-wars").status_code == 200
    finally:
        event.remove(db.engine, "before_cursor_execute", record)

    touched = [s for s in seen if re.search(r'\bFROM\s+reading\b', s, re.I)]
    assert not touched, "the history view loaded readings:\n  " + "\n  ".join(touched)


# --- one session ------------------------------------------------------------

def test_a_session_page_renders_its_summary(signed_in, floor):
    body = signed_in.get(f"/rails/session/{floor['uids'][0]}").get_data(as_text=True)
    assert "HELD THE WINDOW" in body
    assert "held detail" in body
    assert "5.0100" in body, "the powered mean GATBOX sent"


def test_an_unknown_session_is_404(signed_in, floor):
    assert signed_in.get("/rails/session/" + "f" * 32).status_code == 404


def test_an_over_range_reading_is_null_not_zero(signed_in, floor):
    """A zero would draw a dive to 0 V that the meter never reported, on a chart whose whole
    purpose is spotting dropouts."""
    data = island(signed_in.get(f"/rails/session/{floor['uids'][0]}").get_data(as_text=True),
                  "trace-data")
    assert len(data["points"]) == 4
    ol = [p for p in data["points"] if p["ol"]]
    assert len(ol) == 1
    assert ol[0]["y"] is None, f"over-range reached the chart as {ol[0]['y']!r}"
    assert 0 not in [p["y"] for p in data["points"]]


def test_the_trace_x_axis_is_relative_seconds(signed_in, floor):
    """From the Pi's monotonic uptime, so it stays right when the wall clock does not."""
    data = island(signed_in.get(f"/rails/session/{floor['uids'][0]}").get_data(as_text=True),
                  "trace-data")
    assert [p["x"] for p in data["points"]] == [0.0, 0.5, 1.0, 1.5]


def test_the_window_is_a_flat_band_within_one_session(signed_in, floor):
    data = island(signed_in.get(f"/rails/session/{floor['uids'][0]}").get_data(as_text=True),
                  "trace-data")
    assert data["lo"] == 4.75 and data["hi"] == 5.25 and data["alarm"] == 5.775


def test_a_flagged_reading_keeps_its_state(signed_in, floor):
    data = island(signed_in.get(f"/rails/session/{floor['uids'][0]}").get_data(as_text=True),
                  "trace-data")
    assert [p["alarm"] for p in data["points"]] == ["ok", "ok", "spike", None]


def test_an_unverified_clock_is_said_out_loud(signed_in, floor):
    """The Pi records when it had no NTP. A confidently wrong x-axis with no caveat is worse
    than one that says so."""
    body = signed_in.get(f"/rails/session/{floor['uids'][2]}").get_data(as_text=True)
    assert "unverified" in body
    assert "times below may be wrong" in body


def test_a_verified_clock_adds_no_caveat(signed_in, floor):
    body = signed_in.get(f"/rails/session/{floor['uids'][0]}").get_data(as_text=True)
    assert "times below may be wrong" not in body


def test_the_readings_table_shows_the_meter_face(signed_in, floor):
    """raw and unit as the meter printed them, not the normalised value."""
    body = signed_in.get(f"/rails/session/{floor['uids'][0]}").get_data(as_text=True)
    assert "over-range" in body
    assert "5.010" in body


def test_a_session_with_no_window_has_no_verdict(signed_in, app, floor):
    """A bench profile has nothing to pass or fail. That is not the same as passing."""
    from app.extensions import db
    from app.models import Device, RailSession

    with app.app_context():
        device = Device.query.filter_by(name="bench").one()
        s = RailSession(uid="b" * 32, device_id=device.id, game_id=floor["widget"],
                        file="rail_20260926_010000.csv", started=_dt(26),
                        profile_id="resistance", profile_label="Resistance",
                        profile_kind="bench", mode="OHM", verdict=None)
        db.session.add(s)
        db.session.commit()

    body = signed_in.get("/rails/session/" + "b" * 32).get_data(as_text=True)
    assert "NO WINDOW" in body
    assert "nothing to pass or fail" in body
    assert "HELD" not in body, "a missing verdict must not read as a pass"


# --- the panels -------------------------------------------------------------

def test_the_machine_page_links_to_the_history(signed_in, floor):
    body = signed_in.get(f"/game/{floor['widget']}").get_data(as_text=True)
    assert "/rails/machine/widget-wars" in body
    assert "Over-voltage" in body, "the panel shows the latest verdict"
    assert "3 sessions measured" in body


def test_a_machine_with_no_sessions_gets_no_panel(signed_in, floor):
    body = signed_in.get(f"/game/{floor['quiet']}").get_data(as_text=True)
    assert "/rails/machine/quiet-cabinet" not in body


def test_the_work_order_form_links_to_the_history(signed_in, floor):
    """Where a scanned cabinet label lands, so the history is one tap away."""
    body = signed_in.get(f"/maintenance/game/{floor['widget']}").get_data(as_text=True)
    assert "/rails/machine/widget-wars" in body
