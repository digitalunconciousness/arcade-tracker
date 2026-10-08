"""CSRF is enforced everywhere, and every form can satisfy it.

The rest of the suite runs with CSRF off so it can post bare form data; this module turns it
on (``WTF_CSRF_ENABLED=True``, the production setting) and checks three things:

1. every ``<form method="post">`` on every page, for every role, carries a ``csrf_token``;
2. every POST route refuses a request without one (400), signed in as admin so no role check
   gets there first;
3. a real round trip (GET the page, POST its token back) still works, so turning CSRF on did
   not lock anyone out.

Two blueprints are exempt by design, each with its reason in its own module: the device API
(``/api/v1``, a bearer token and no cookie to forge) and the coin-door report form
(``/report/<token>``, where the token in the URL is the authorisation).
"""
from __future__ import annotations

import re

import pytest

from char_support import LEVEL, PASSWORD
from test_routes_get import PAGES
from test_routes_post import POSTS

TOKEN = re.compile(r'name="csrf_token"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="csrf_token"')
POST_FORM = re.compile(r"<form\b[^>]*\bmethod=[\"']?post[\"']?[^>]*>(.*?)</form>", re.S | re.I)


@pytest.fixture()
def app(_isolate_environment):
    """The application exactly as deployed: CSRF on (overrides tests/conftest.py's app)."""
    from app import create_app
    from app.extensions import db

    application = create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def token_from(html: str) -> str:
    m = TOKEN.search(html)
    assert m, "no csrf_token on the page"
    return m.group(1) or m.group(2)


def login(client, role):
    html = client.get("/login").get_data(as_text=True)
    resp = client.post("/login", data={"username": f"test-{role}", "password": PASSWORD,
                                       "csrf_token": token_from(html)})
    assert resp.status_code == 302, f"login as {role} failed under CSRF"


def test_no_template_has_a_post_form_without_a_token():
    """Static, so a form that only renders for some data (an active alert, a photo) is
    checked too. ``formmethod="post"`` on a button is refused outright: it borrows the
    enclosing form, which is usually a GET form with no token."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "templates"
    bad = []
    for path in sorted(root.rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        for m in POST_FORM.finditer(text):
            if "csrf_token" not in m.group(1) and "hidden_tag()" not in m.group(1):
                bad.append(f"{path.name}:{text[:m.start()].count(chr(10)) + 1}")
        if re.search(r'formmethod=["\']?post', text, re.I):
            bad.append(f"{path.name}: formmethod=post")
    assert bad == []


def test_csrf_is_enforced_by_default(app):
    assert app.config.get("WTF_CSRF_CHECK_DEFAULT", True) is True


HTML = [p for p in PAGES if p[5] == "text/html"]


@pytest.mark.parametrize("role", [r for r in LEVEL if r != "anon"])
def test_every_post_form_carries_a_token(client, floor, role):
    login(client, role)
    missing = []
    for rule, build, minimum, *_ in HTML:
        if LEVEL[role] < LEVEL[minimum]:
            continue
        html = client.get(build(floor)).get_data(as_text=True)
        for body in POST_FORM.findall(html):
            if 'name="csrf_token"' not in body:
                missing.append(rule)
    assert missing == [], f"POST forms without a csrf_token: {sorted(set(missing))}"


def test_the_login_and_report_forms_carry_a_token(client, floor):
    from app.extensions import db
    from app.models import Game

    game = db.session.get(Game, floor["raider"])
    token = game.mint_report_token()
    db.session.commit()
    for url in ("/login", f"/report/{token}"):
        for body in POST_FORM.findall(client.get(url).get_data(as_text=True)):
            assert 'name="csrf_token"' in body, url


@pytest.mark.parametrize("build", [b for b, _ in POSTS])
def test_a_post_without_a_token_is_refused(client, floor, build):
    login(client, "admin")
    resp = client.post(build(floor), data={})
    assert resp.status_code == 400


def test_a_real_round_trip_still_works(client, floor):
    """GET a page, post its token back: an operator records plays with CSRF on."""
    from app.extensions import db
    from app.models import Game

    login(client, "operator")
    html = client.get(f"/record_plays/{floor['raider']}").get_data(as_text=True)
    resp = client.post(f"/record_plays/{floor['raider']}", data={
        "coin_count": "150", "date": "2026-10-01", "csrf_token": token_from(html)})
    assert resp.status_code == 302
    db.session.expire_all()
    assert db.session.get(Game, floor["raider"]).total_plays == 50


def test_an_expired_or_missing_token_explains_itself(client, floor):
    """A phone left on a form overnight gets a page that says what happened, not a bare 400."""
    login(client, "operator")
    resp = client.post(f"/record_plays/{floor['raider']}", data={"coin_count": "150"})
    assert resp.status_code == 400
    body = resp.get_data(as_text=True)
    assert "expired" in body.lower() and "<html" in body.lower()


def test_tokens_do_not_expire_while_the_session_lives(app):
    """The default one-hour limit would fail a form opened at the start of a shift."""
    assert app.config["WTF_CSRF_TIME_LIMIT"] is None
