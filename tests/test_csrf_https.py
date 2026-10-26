"""Forms still post through the tunnel once the app knows it is HTTPS.

Regression (2026-10-26): Step 5.1 let the app see the tunnel's HTTPS. Over HTTPS Flask-WTF also
requires a Referer from this host (WTF_CSRF_SSL_STRICT), and the app told browsers to send no
Referer at all (``Referrer-Policy: no-referrer``), so every form posted through the tunnel was
refused, the login included. The cookie tests ran with CSRF off and the CSRF tests over HTTP,
so neither saw it. This runs both at once, as production does.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import PASSWORD
from seed import seed_floor
from test_csrf import token_from

HOST = "https://tracker.example"          # a documentation-style name, not the real one
TUNNEL = {"REMOTE_ADDR": "127.0.0.1"}
FORWARDED = {"X-Forwarded-Proto": "https"}


@pytest.fixture()
def app(_isolate_environment):
    from app import create_app
    from app.extensions import db

    application = create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    with application.app_context():
        db.create_all()
        seed_floor()
        yield application
        db.session.remove()
        db.drop_all()


def browser_referer(response, page: str) -> dict:
    """The Referer a browser sends when posting a form from *page*, under the page's policy."""
    policy = response.headers.get("Referrer-Policy", "")
    if policy in ("no-referrer", ""):
        return {} if policy else {"Referer": HOST + page}
    assert policy in ("same-origin", "strict-origin-when-cross-origin", "origin")
    return {"Referer": HOST + page if policy == "same-origin" else HOST + "/"}


def test_signing_in_through_the_tunnel_works(app):
    client = app.test_client()
    page = client.get("/login", base_url=HOST, environ_base=TUNNEL, headers=FORWARDED)
    resp = client.post("/login", base_url=HOST, environ_base=TUNNEL,
                       headers={**FORWARDED, **browser_referer(page, "/login")},
                       data={"username": "test-operator", "password": PASSWORD,
                             "csrf_token": token_from(page.get_data(as_text=True))})
    assert resp.status_code == 302, resp.get_data(as_text=True)[:200]
    assert client.get("/", base_url=HOST, environ_base=TUNNEL,
                      headers=FORWARDED).status_code == 200


def test_without_a_referer_https_forms_are_refused(app):
    """Why the policy matters: the strict check is real, and no-referrer trips it."""
    client = app.test_client()
    page = client.get("/login", base_url=HOST, environ_base=TUNNEL, headers=FORWARDED)
    resp = client.post("/login", base_url=HOST, environ_base=TUNNEL, headers=FORWARDED,
                       data={"username": "test-operator", "password": PASSWORD,
                             "csrf_token": token_from(page.get_data(as_text=True))})
    assert resp.status_code == 400


def test_the_policy_never_sends_a_url_to_another_site(app):
    """The coin-door token is in its URL; same-origin keeps it off every other site."""
    resp = app.test_client().get("/login")
    assert resp.headers["Referrer-Policy"] == "same-origin"
