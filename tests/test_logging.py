"""Structured logging (Step 5.5): one key=value line per event, with the request's ID."""
from __future__ import annotations

import logging

import pytest

from app.logs import Logfmt

PASSWORD = "Correct-Horse-9"


@pytest.fixture()
def lines(caplog):
    """Everything logged, formatted exactly as the journal receives it."""
    caplog.set_level(logging.INFO)
    fmt = Logfmt()

    def read():
        return [fmt.format(r) for r in caplog.records]
    return read


@pytest.fixture()
def staff(app):
    from app.extensions import db
    from app.models import User
    from app.security import utils

    u = User(username="log-tester", role="operator", must_change_password=False)
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    utils.failed_login_attempts.clear()
    return u


def test_security_events_at_info_are_kept(client, staff, lines):
    """F-23: the logger kept warnings only, so these were dropped."""
    client.post("/login", data={"username": "log-tester", "password": "wrong"})
    client.post("/login", data={"username": "log-tester", "password": PASSWORD})
    out = "\n".join(lines())
    assert "event=LOGIN_FAILED" in out and "event=LOGIN_SUCCESS" in out
    assert "level=INFO logger=arcade.security" in out


def test_every_line_of_a_request_shares_its_id(client, staff, lines):
    resp = client.post("/login", data={"username": "log-tester", "password": "wrong"})
    rid = resp.headers["X-Request-ID"]
    mine = [line for line in lines() if f"request_id={rid}" in line]
    assert any("event=LOGIN_FAILED" in line for line in mine)
    assert any("event=request" in line for line in mine)


def test_one_request_line_per_page_and_none_for_static_files(client, staff, lines):
    client.get("/login")
    client.get("/static/css/base.css")
    requests = [line for line in lines() if "event=request" in line]
    assert len(requests) == 1
    assert "method=GET path=/login status=200" in requests[0] and "ms=" in requests[0]


def test_the_request_line_names_the_signed_in_user(client, staff, lines):
    client.post("/login", data={"username": "log-tester", "password": PASSWORD})
    client.get("/")
    assert any("path=/ status=200" in line and "user=log-tester" in line for line in lines())


def test_a_coin_door_token_never_reaches_the_log(client, app, lines):
    """The URL is the credential, so the route is logged by its pattern."""
    from app.extensions import db
    from app.models import Game

    game = Game(name="Galaxy Runner", barcode="galaxy-runner", location="Floor")
    db.session.add(game)
    db.session.commit()
    token = game.mint_report_token()
    db.session.commit()
    client.get(f"/report/{token}")
    client.post(f"/report/{token}", data={"issue_description": "Coin jammed"})
    out = "\n".join(lines())
    assert token not in out
    assert "path=/report/<token>" in out


@pytest.mark.parametrize(("remote", "ray", "expected"), [
    ("127.0.0.1", "8a1f2c3d4e5f6a7b-LHR", "8a1f2c3d4e5f6a7b-LHR"),   # the tunnel
    ("192.0.2.10", "8a1f2c3d4e5f6a7b-LHR", None),                    # LAN can't choose it
    ("127.0.0.1", "not a ray; x=1", None),
])
def test_the_request_id_is_cloudflares_ray_only_from_the_tunnel(client, remote, ray, expected):
    rid = client.get("/login", environ_base={"REMOTE_ADDR": remote},
                     headers={"CF-Ray": ray}).headers["X-Request-ID"]
    if expected:
        assert rid == expected
    else:
        assert rid != ray and len(rid) == 16


def test_an_error_is_logged_with_its_traceback_on_one_line_and_its_reference_shown(app, lines):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.route("/boom-for-test")
    def boom():
        raise RuntimeError("synthetic failure\nsecond line")

    resp = app.test_client().get("/boom-for-test")
    rid = resp.headers["X-Request-ID"]
    assert resp.status_code == 500
    assert rid in resp.get_data(as_text=True), "the error page shows the reference"
    errors = [line for line in lines() if "level=ERROR" in line]
    assert errors and f"request_id={rid}" in errors[0]
    assert "\n" not in errors[0], "a traceback must not split one event across journal lines"
    assert "RuntimeError" in errors[0]


@pytest.mark.parametrize(("value", "written"), [
    ("plain", "plain"),
    ("two words", '"two words"'),
    ('say "hi"', '"say \\"hi\\""'),
    ("line\nbreak", '"line\\nbreak"'),
    ("", '""'),
    (None, "-"),
])
def test_values_are_quoted_only_when_they_need_it(value, written):
    from app.logs import _value

    assert _value(value) == written
