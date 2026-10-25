"""Login protection (F-23): who the visitor is, and how many wrong guesses they get.

Through the tunnel every request comes from 127.0.0.1; Cloudflare's CF-Connecting-IP names the
real visitor. A whole arcade shares one public address, so only failures are limited.
"""
from __future__ import annotations

import pytest

PASSWORD = "Correct-Horse-9"


def tunnel(ip):
    return {"environ_base": {"REMOTE_ADDR": "127.0.0.1"}, "headers": {"CF-Connecting-IP": ip}}


@pytest.fixture()
def staff(app):
    from app.extensions import db
    from app.models import User

    u = User(username="floor-tech", role="operator", must_change_password=False)
    u.set_password(PASSWORD)
    db.session.add(u)
    db.session.commit()
    from app.security import utils

    utils.failed_login_attempts.clear()
    yield u
    utils.failed_login_attempts.clear()


def attempt(client, password, via):
    return client.post("/login", data={"username": "floor-tech", "password": password}, **via)


# --- who is asking ------------------------------------------------------------------------------

@pytest.mark.parametrize(("remote", "headers", "expected"), [
    ("127.0.0.1", {"CF-Connecting-IP": "198.51.100.7"}, "198.51.100.7"),   # the tunnel
    ("127.0.0.1", {}, "127.0.0.1"),                                         # local, no header
    ("127.0.0.1", {"CF-Connecting-IP": "not-an-ip"}, "127.0.0.1"),
    ("192.0.2.10", {"CF-Connecting-IP": "198.51.100.7"}, "192.0.2.10"),    # LAN can't claim
    ("192.0.2.10", {"X-Forwarded-For": "198.51.100.7"}, "192.0.2.10"),
    ("127.0.0.1", {"X-Real-IP": "198.51.100.7"}, "127.0.0.1"),              # never believed
])
def test_the_visitor_address_is_only_taken_from_the_tunnel(app, remote, headers, expected):
    from app.security.https import client_ip

    with app.test_request_context(environ_base={"REMOTE_ADDR": remote}, headers=headers):
        assert client_ip() == expected


# --- the lockout ---------------------------------------------------------------------------------

def test_a_stranger_through_the_tunnel_cannot_lock_out_staff(client, staff):
    """Before: every tunnel request was 127.0.0.1, so five wrong guesses from anywhere locked
    the real user out."""
    for _ in range(6):
        attempt(client, "wrong", tunnel("203.0.113.66"))
    resp = attempt(client, PASSWORD, tunnel("198.51.100.7"))
    assert resp.status_code == 302


def test_the_guesser_is_locked_out(client, staff):
    for _ in range(5):
        attempt(client, "wrong", tunnel("203.0.113.66"))
    html = attempt(client, PASSWORD, tunnel("203.0.113.66")).get_data(as_text=True)
    assert "temporarily locked" in html


def test_a_spoofed_header_does_not_dodge_the_lockout(client, staff):
    """X-Forwarded-For used to be believed from anyone, so a new value each try meant no lockout."""
    lan = {"REMOTE_ADDR": "192.0.2.10"}
    for i in range(5):
        client.post("/login", data={"username": "floor-tech", "password": "wrong"},
                    environ_base=lan, headers={"X-Forwarded-For": f"198.51.100.{i}"})
    html = client.post("/login", data={"username": "floor-tech", "password": PASSWORD},
                       environ_base=lan).get_data(as_text=True)
    assert "temporarily locked" in html


# --- the rate limit ------------------------------------------------------------------------------

def test_guessing_many_usernames_is_rate_limited(client, staff):
    """The lockout is per username; the limit is per visitor, so spraying names hits it."""
    codes = [client.post("/login", data={"username": f"user{i}", "password": "wrong"},
                         **tunnel("203.0.113.66")).status_code for i in range(11)]
    assert codes[:10] == [200] * 10 and codes[10] == 429


def test_the_limit_page_says_what_to_do(client, staff):
    for i in range(11):
        resp = client.post("/login", data={"username": f"user{i}", "password": "wrong"},
                           **tunnel("203.0.113.66"))
    html = resp.get_data(as_text=True)
    assert "Too many attempts" in html and "Wait a minute" in html


def test_successful_sign_ins_do_not_spend_the_budget(client, staff):
    """A whole arcade shares one public address; staff signing in correctly never hit it."""
    for _ in range(15):
        assert attempt(client, PASSWORD, tunnel("198.51.100.7")).status_code == 302
        client.post("/logout", **tunnel("198.51.100.7"))
    assert attempt(client, "wrong", tunnel("198.51.100.7")).status_code == 200


def test_another_visitor_is_unaffected_by_a_limited_one(client, staff):
    for i in range(11):
        client.post("/login", data={"username": f"user{i}", "password": "wrong"},
                    **tunnel("203.0.113.66"))
    assert attempt(client, PASSWORD, tunnel("198.51.100.7")).status_code == 302


def test_a_collection_round_fits_under_the_site_ceiling(client, staff):
    """The old default was 200 pages an hour, shared by everyone through the tunnel."""
    attempt(client, PASSWORD, tunnel("198.51.100.7"))
    codes = {client.get("/", **tunnel("198.51.100.7")).status_code for _ in range(300)}
    assert codes == {200}
