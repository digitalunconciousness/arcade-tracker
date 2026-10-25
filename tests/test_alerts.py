"""Alerts (feature step 6): who gets told what, when, and that it gets there.

Owner's decisions (2026-10-25): ntfy (self-hosted) and Discord; separate channels each picking
their events; all seven events; hold outside opening hours and send at opening; a daily
summary at opening. Nothing here reaches the network: requests.post is replaced.
"""
from __future__ import annotations

import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import flashes, login
from seed import seed_floor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVERYTHING = "coin_door,machine_down,rail_window,low_stock,pm_due,round_flag,part_request,summary"
WEBHOOK = "https://discord.com/api/webhooks/123/secret-part"


def naive(*args) -> dt.datetime:
    """A wall-clock time, as the arcade's clock and the database's columns keep them."""
    return dt.datetime(*args)  # noqa: DTZ001 -- naive on purpose, see above


@pytest.fixture()
def floor(app):
    app.config["BASE_URL"] = "https://arcade.example"
    return seed_floor()


class Wire:
    """Stands in for requests.post: records each call, answers with *status*."""

    def __init__(self):
        self.calls, self.status, self.boom = [], 200, None

    def __call__(self, url, timeout=None, **kw):
        import requests

        if self.boom:
            raise requests.ConnectionError(f"failed to reach {url}")
        self.calls.append((url, kw))
        return type("R", (), {"status_code": self.status})()


@pytest.fixture()
def wire(monkeypatch):
    import requests

    w = Wire()
    monkeypatch.setattr(requests, "post", w)
    return w


def channel(name="Techs", events=EVERYTHING, *, ntfy="http://ntfy.lan/arcade-techs",
            discord=None, quiet=True, token=None):
    from app.extensions import db
    from app.models import AlertChannel

    c = AlertChannel(name=name, events=events, ntfy_url=ntfy, discord_webhook=discord,
                     ntfy_token=token, quiet=quiet)
    db.session.add(c)
    db.session.commit()
    return c.id


def queued(event=None):
    from app.extensions import db
    from app.models import Alert

    db.session.expire_all()
    q = Alert.query
    if event:
        q = q.filter_by(event=event)
    return q.order_by(Alert.id).all()


def hours(opens, closes):
    from app.extensions import db
    from app.models import Setting

    Setting.put("open_time", opens)
    Setting.put("close_time", closes)
    db.session.commit()


# --- the seven events ---------------------------------------------------------------------------

def test_a_coin_door_report(client, floor):
    from app.extensions import db
    from app.models import Game

    channel()
    game = db.session.get(Game, floor["raider"])
    token = game.mint_report_token()
    db.session.commit()
    client.post(f"/report/{token}", data={"reported_by": "Sam Tester", "issue_description": "Screen went black"})
    (a,) = queued("coin_door")
    assert (a.title, a.body) == ("Coin-door report: Neon Raider",
                                 "From Sam Tester: Screen went black")
    assert a.path.startswith("/maintenance_detail/") and a.status == "pending"


def test_a_machine_marked_down_by_an_order_or_by_hand(client, floor):
    channel()
    login(client, "manager")
    client.post(f"/maintenance/game/{floor['raider']}", data={
        "issue_description": "Dead", "status": "Open", "machine_down": "yes"})
    client.post("/bulk_update_games", data={"action": "set_not_working",
                                           "game_ids": [floor["courier"]]})
    titles = [a.title for a in queued("machine_down")]
    assert titles == ["Down: Neon Raider", "Down: Star Courier"]
    assert queued("machine_down")[0].path == f"/game/{floor['raider']}"


def test_a_rail_out_of_its_window(app, floor):
    from app.extensions import db
    from app.models import RailSession

    channel()
    db.session.add(RailSession(uid="e" * 32, device_id=1, game_id=floor["raider"],
                               file="rail_x.csv", started=naive(2026, 10, 1),
                               ended=naive(2026, 10, 1), duration_s=1.0, samples=1,
                               rail="+12V", mode="VDC", verdict="over",
                               verdict_detail="peak 13.1 V"))
    db.session.add(RailSession(uid="f" * 32, device_id=1, game_id=floor["raider"],
                               file="rail_y.csv", started=naive(2026, 10, 1),
                               ended=naive(2026, 10, 1), duration_s=1.0, samples=1,
                               verdict="held"))
    db.session.commit()
    (a,) = queued("rail_window")
    assert (a.title, a.body, a.path) == ("Rail over its window: Neon Raider",
                                         "+12V peak 13.1 V", f"/rails/session/{'e' * 32}")


def test_a_part_dropping_to_its_minimum(client, floor):
    channel()
    login(client, "operator")
    client.post(f"/inventory/{floor['belt']}/adjust_stock", data={
        "adjustment_type": "used", "quantity": "8", "reason": ""})
    (a,) = queued("low_stock")
    assert (a.title, a.body) == ("Low stock: Drive Belt", "2 left; the minimum is 2.")


def test_preventive_maintenance_coming_due(client, floor):
    from app.extensions import db
    from app.models import MaintenanceTask

    channel()
    db.session.add(MaintenanceTask(name="Clean the coin mech", every_plays=10,
                                   applies_to="machine", game_id=floor["raider"]))
    db.session.commit()
    login(client, "operator")
    client.post(f"/record_plays/{floor['raider']}", data={"coin_count": "160"})
    (a,) = queued("pm_due")
    assert a.title == "Maintenance due: Neon Raider"
    assert a.body.startswith("Preventive maintenance: Clean the coin mech.")


def test_a_round_flag(client, floor):
    channel()
    login(client, "operator")
    client.post(f"/round/{floor['raider']}", data={"coin_count": "140"})
    (a,) = queued("round_flag")
    assert a.title == "Neon Raider: no plays since the last reading" and a.path == "/round/"


def test_a_part_request_shipped(client, floor):
    channel()
    login(client, "manager")
    client.post(f"/inventory/requests/{floor['request']}/update", data={"status": "Shipped"})
    (a,) = queued("part_request")
    assert a.title == "Part request shipped: Drive Belt"


# --- who gets what ------------------------------------------------------------------------------

def test_each_channel_gets_only_its_events_on_each_of_its_targets(app, floor):
    from app.services.alerts import notify

    techs = channel("Techs", "coin_door", discord=WEBHOOK)
    channel("Manager", "low_stock")
    notify("coin_door", "Coin-door report: X")
    from app.extensions import db
    db.session.commit()
    rows = queued()
    assert {(a.channel_id, a.target) for a in rows} == {(techs, "ntfy"), (techs, "discord")}


def test_an_alert_is_saved_with_its_cause_or_not_at_all(app, floor):
    from app.extensions import db
    from app.services.alerts import notify

    channel()
    notify("coin_door", "Never happened")
    db.session.rollback()
    assert queued() == []


def test_a_paused_channel_gets_nothing(app, floor):
    from app.extensions import db
    from app.models import AlertChannel
    from app.services.alerts import notify

    db.session.get(AlertChannel, channel()).active = False
    notify("coin_door", "x")
    db.session.commit()
    assert queued() == []


# --- delivery -----------------------------------------------------------------------------------

def test_ntfy_gets_title_message_link_priority_and_token(app, floor, wire):
    from app.extensions import db
    from app.services.alerts import deliver, notify

    channel(token="tk_secret")
    notify("coin_door", "Coin-door report: Neon Raider", "Screen went black",
           "/maintenance_detail/9")
    db.session.commit()
    assert deliver()["sent"] == 1
    (url, kw), = wire.calls
    assert url == "http://ntfy.lan"
    assert kw["json"] == {"topic": "arcade-techs", "title": "Coin-door report: Neon Raider",
                          "message": "Screen went black", "priority": 4,
                          "tags": ["rotating_light"],
                          "click": "https://arcade.example/maintenance_detail/9"}
    assert kw["headers"] == {"Authorization": "Bearer tk_secret"}
    assert queued()[0].status == "sent"


def test_discord_gets_text_and_never_pings(app, floor, wire):
    from app.extensions import db
    from app.services.alerts import deliver, notify

    channel(ntfy=None, discord=WEBHOOK)
    notify("coin_door", "Coin-door report", "@everyone free tokens", "/x")
    db.session.commit()
    deliver()
    (url, kw), = wire.calls
    assert url == WEBHOOK
    assert kw["json"]["content"] == ("**Coin-door report**\n@everyone free tokens\n"
                                     "<https://arcade.example/x>")
    assert kw["json"]["allowed_mentions"] == {"parse": []}


def test_a_failure_is_retried_later_and_never_records_the_address(app, floor, wire):
    from app.extensions import db
    from app.services.alerts import deliver, notify

    channel(ntfy=None, discord=WEBHOOK)
    notify("coin_door", "x")
    db.session.commit()
    wire.boom = True
    now = naive(2026, 10, 25, 12, 0)
    queued()[0].created_at = now
    db.session.commit()
    assert deliver(now=now)["failed"] == 1
    a = queued()[0]
    assert (a.status, a.attempts, a.error) == ("pending", 1, "ConnectionError")
    assert "secret" not in (a.error or "")
    assert deliver(now=now + dt.timedelta(seconds=30))["sent"] == 0, "not before its next try"
    wire.boom = False
    assert deliver(now=now + dt.timedelta(minutes=2))["sent"] == 1


def test_it_gives_up_after_a_day(app, floor, wire):
    from app.extensions import db
    from app.services.alerts import deliver, notify

    channel()
    notify("coin_door", "x")
    db.session.commit()
    wire.status = 500
    queued()[0].created_at = naive(2026, 10, 1)
    db.session.commit()
    deliver(now=naive(2026, 10, 3))
    assert (queued()[0].status, queued()[0].error) == ("failed", "HTTP 500")


# --- opening hours ------------------------------------------------------------------------------

def test_held_while_closed_then_one_message_at_opening(app, floor, wire):
    from app.extensions import db
    from app.services.alerts import deliver, notify

    channel()
    always = channel("Manager", quiet=False, ntfy="http://ntfy.lan/arcade-manager")
    hours("10:00", "22:00")
    night = naive(2026, 10, 25, 23, 30)
    notify("coin_door", "Coin-door report: A", now=night)
    notify("machine_down", "Down: B", now=night)
    db.session.commit()
    assert {a.status for a in queued() if a.channel_id != always} == {"held"}
    assert {a.status for a in queued() if a.channel_id == always} == {"pending"}

    deliver(now_local=night)
    assert len(wire.calls) == 2, "the always-send channel only"
    wire.calls.clear()
    deliver(now_local=naive(2026, 10, 26, 10, 1))
    titles = [kw["json"]["title"] for _, kw in wire.calls]
    assert "2 alerts while closed" in titles
    digest = next(kw["json"] for _, kw in wire.calls if kw["json"]["title"].startswith("2 "))
    assert digest["message"] == "- Coin-door report: A\n- Down: B"


def test_closing_after_midnight(app, floor):
    from app.services.alerts import is_open

    hours("18:00", "02:00")
    assert is_open(naive(2026, 10, 25, 1, 30))
    assert not is_open(naive(2026, 10, 25, 3, 0))


def test_no_hours_means_always_open_and_no_summary(app, floor, wire):
    from app.services.alerts import deliver, is_open

    channel()
    assert is_open(naive(2026, 10, 25, 4, 0))
    assert deliver(now_local=naive(2026, 10, 25, 4, 0))["summaries"] == 0


def test_the_daily_summary_goes_once_at_opening(app, floor, wire):
    from app.services.alerts import deliver

    channel()
    channel("Bar", "coin_door", ntfy="http://ntfy.lan/bar")
    hours("10:00", "22:00")
    assert deliver(now_local=naive(2026, 10, 25, 9, 59))["summaries"] == 0
    assert deliver(now_local=naive(2026, 10, 25, 10, 0))["summaries"] == 1
    assert deliver(now_local=naive(2026, 10, 25, 10, 1))["summaries"] == 0
    (summary,) = [kw["json"] for _, kw in wire.calls if kw["json"]["title"] == "Today's summary"]
    assert "Machines down: 0" in summary["message"] and "Parts low: 1" in summary["message"]
    assert deliver(now_local=naive(2026, 10, 26, 10, 0))["summaries"] == 1


# --- the admin page -----------------------------------------------------------------------------

def test_an_admin_sets_up_a_channel(client, floor):
    from app.models import AlertChannel

    login(client, "admin")
    resp = client.post("/admin/alerts/new", data={
        "name": "Manager", "events": ["low_stock", "round_flag"], "discord_webhook": WEBHOOK,
        "quiet": "1", "active": "1"})
    assert resp.status_code == 302
    c = AlertChannel.query.filter_by(name="Manager").one()
    assert (c.event_list, c.discord_webhook, c.ntfy_url, c.quiet) == (
        ["low_stock", "round_flag"], WEBHOOK, None, True)


def test_secrets_are_never_shown_back_and_blank_keeps_them(client, floor):
    from app.extensions import db
    from app.models import AlertChannel

    cid = channel(discord=WEBHOOK, token="tk_secret")
    login(client, "admin")
    html = client.get(f"/admin/alerts/{cid}/edit").get_data(as_text=True)
    assert "secret-part" not in html and "tk_secret" not in html
    assert "Saved; leave blank to keep it" in html
    client.post(f"/admin/alerts/{cid}/edit", data={
        "name": "Techs", "events": ["coin_door"], "ntfy_url": "http://ntfy.lan/arcade-techs",
        "active": "1", "remove_ntfy_token": "1"})
    db.session.expire_all()
    c = db.session.get(AlertChannel, cid)
    assert (c.discord_webhook, c.ntfy_token) == (WEBHOOK, None)


@pytest.mark.parametrize(("form", "message"), [
    ({"name": "", "events": ["coin_door"], "ntfy_url": "http://ntfy.lan/t"}, "Name the channel"),
    ({"name": "A", "events": [], "ntfy_url": "http://ntfy.lan/t"}, "Pick at least one"),
    ({"name": "A", "events": ["coin_door"]}, "Give an ntfy topic, a Discord webhook"),
    ({"name": "A", "events": ["coin_door"], "ntfy_url": "ftp://ntfy.lan/t"}, "starts with http"),
    ({"name": "A", "events": ["coin_door"], "ntfy_url": "http://ntfy.lan/a b"}, "End it with"),
    ({"name": "A", "events": ["coin_door"], "discord_webhook": "https://evil.example/api/webhooks/1"},
     "isn&#39;t a Discord webhook"),
])
def test_a_bad_channel_is_refused(client, floor, form, message):
    from app.models import AlertChannel

    before = AlertChannel.query.count()
    login(client, "admin")
    resp = client.post("/admin/alerts/new", data=form)
    assert resp.status_code == 400 and message in resp.get_data(as_text=True)
    assert AlertChannel.query.count() == before


def test_the_test_button_reports_what_happened(client, floor, wire):
    cid = channel(discord=WEBHOOK)
    login(client, "admin")
    wire.status = 404
    client.post(f"/admin/alerts/{cid}/test")
    messages = flashes(client)
    expected = ("ntfy: not sent (HTTP 404). Check the address, and that this server can "
                "reach it.")
    assert ("error", expected) in messages
    assert len(wire.calls) == 2 and all(a.status == "failed" for a in queued("test"))


def test_opening_hours_are_checked(client, floor):
    from app.models import Setting

    login(client, "admin")
    client.post("/admin/alerts/hours", data={"open_time": "10:00", "close_time": ""})
    assert Setting.get("open_time") is None
    client.post("/admin/alerts/hours", data={"open_time": "10:00", "close_time": "22:00"})
    assert (Setting.get("open_time"), Setting.get("close_time")) == ("10:00", "22:00")


def test_deleting_a_channel_takes_its_log(client, floor):
    from app.services.alerts import notify

    cid = channel()
    notify("coin_door", "x")
    from app.extensions import db
    db.session.commit()
    login(client, "admin")
    client.post(f"/admin/alerts/{cid}/delete")
    assert queued() == []


# --- the sender script and the migration --------------------------------------------------------

def test_the_script_sends_and_prints_counts(app, floor, wire, capsys):
    import importlib.util

    from app.extensions import db
    from app.services.alerts import notify

    channel()
    notify("coin_door", "x")
    db.session.commit()
    spec = importlib.util.spec_from_file_location("send_alerts",
                                                  os.path.join(ROOT, "scripts", "send_alerts.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main(app=app) == 0
    assert "sent=1" in capsys.readouterr().out


def test_the_timer_runs_the_script_every_minute():
    from pathlib import Path

    unit = (Path(ROOT) / "deploy" / "arcade-tracker-alerts.service").read_text()
    timer = (Path(ROOT) / "deploy" / "arcade-tracker-alerts.timer").read_text()
    assert "ExecStart=/opt/arcade-tracker-venv/bin/python scripts/send_alerts.py" in unit
    assert "User=arcade-tracker" in unit and "OnUnitActiveSec=1min" in timer


def test_the_migration_round_trips(app, floor):
    import sqlalchemy as sa
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db

    def migrate(step, revision):
        db.session.commit()
        step(directory=os.path.join(ROOT, "migrations"), revision=revision)

    def tables():
        return set(sa.inspect(db.engine).get_table_names())

    stamp(directory=os.path.join(ROOT, "migrations"), revision="a5b6c7d8e9f0")
    migrate(downgrade, "f4a5b6c7d8e9")
    assert not {"alert", "alert_channel", "app_setting"} & tables()
    migrate(upgrade, "a5b6c7d8e9f0")
    migrate(upgrade, "a5b6c7d8e9f0")
    assert {"alert", "alert_channel", "app_setting"} <= tables()
