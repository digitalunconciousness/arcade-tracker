"""Cookie flags (F-22): Secure through the tunnel, still usable over plain HTTP on the LAN.

The tunnel reaches the app on 127.0.0.1 and says ``X-Forwarded-Proto: https``; a LAN client
connects straight to the server's address over HTTP. See app/security/https.py.
"""
from __future__ import annotations

import pytest

PASSWORD = "Correct-Horse-9"
TUNNEL = {"REMOTE_ADDR": "127.0.0.1"}
LAN = {"REMOTE_ADDR": "192.0.2.10"}       # TEST-NET-1, a documentation address


@pytest.fixture()
def user(app):
    from app.extensions import db
    from app.models import User

    u = User(username="cookie-tester", role="operator", must_change_password=False)
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    return u


def sign_in(client, environ, headers=None):
    return client.post("/login", data={"username": "cookie-tester", "password": PASSWORD,
                                       "remember": "y"},
                       environ_base=environ, headers=headers or {})


def cookies(response):
    return {c.split("=", 1)[0]: c for c in response.headers.getlist("Set-Cookie")}


def test_through_the_tunnel_every_cookie_is_secure(client, user):
    resp = sign_in(client, TUNNEL, {"X-Forwarded-Proto": "https"})
    set = cookies(resp)
    assert {"session", "remember_token"} <= set.keys(), set
    for name, value in set.items():
        assert "; Secure" in value, name
        assert "HttpOnly" in value and "SameSite=Lax" in value, name


def test_on_the_lan_over_http_the_cookies_still_work(client, user):
    resp = sign_in(client, LAN)
    assert resp.status_code == 302
    for name, value in cookies(resp).items():
        assert "Secure" not in value, f"{name} would never come back over plain HTTP"
    assert client.get("/", environ_base=LAN).status_code == 200


def test_a_lan_client_cannot_claim_https(client, user):
    """Only loopback (the tunnel) is trusted to say what the scheme was."""
    resp = sign_in(client, LAN, {"X-Forwarded-Proto": "https"})
    assert all("Secure" not in v for v in cookies(resp).values())


def test_real_https_is_secure_too(client, user):
    resp = client.post("/login", data={"username": "cookie-tester", "password": PASSWORD},
                       base_url="https://localhost")
    assert all("; Secure" in v for v in cookies(resp).values())


def test_secure_is_added_once():
    from app.security.https import secure

    assert secure("a=1; Path=/") == "a=1; Path=/; Secure"
    assert secure("a=1; Path=/; Secure") == "a=1; Path=/; Secure"
    assert secure("secure=1; Path=/") == "secure=1; Path=/; Secure", "the name isn't a flag"


@pytest.mark.parametrize("value", ["", "  ", "your-secret-key-change-this-for-production"])
def test_the_app_refuses_to_start_without_a_secret_key(monkeypatch, value):
    """A random key per start signed everyone out on every restart."""
    from app import create_app

    monkeypatch.setenv("SECRET_KEY", value)
    with pytest.raises(RuntimeError, match="SECRET_KEY is not set"):
        create_app()


def test_the_unit_file_lets_waitress_trust_the_tunnel():
    """waitress 3 drops X-Forwarded-Proto from untrusted peers, so without these flags the
    app never sees that a tunnel request was HTTPS and the fix above does nothing."""
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "arcade-tracker.service"), encoding="utf-8") as fh:
        unit = fh.read()
    exec_start = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert "--trusted-proxy=127.0.0.1" in exec_start
    assert "--trusted-proxy-headers=x-forwarded-proto" in exec_start
    assert "x-forwarded-for" not in exec_start, "client addresses are 5.2's decision"
