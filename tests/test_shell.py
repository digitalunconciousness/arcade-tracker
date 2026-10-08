"""The base shell: error pages, versioned assets, the sign-in page and the service worker."""
from __future__ import annotations

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _sign_in(client, app, role="readonly"):
    from app.extensions import db
    from app.models import User

    user = User(username=f"shell-{role}", role=role, must_change_password=False)
    user.set_password("Synthetic-Passw0rd!")
    db.session.add(user)
    db.session.commit()
    client.post("/login", data={"username": f"shell-{role}", "password": "Synthetic-Passw0rd!"})


def test_an_unknown_page_is_a_styled_404(client, app):
    _sign_in(client, app)
    resp = client.get("/no-such-page")
    body = resp.get_data(as_text=True)
    assert resp.status_code == 404
    assert "Nothing here" in body and 'class="app-header"' in body


def test_a_missing_record_is_the_same_404(client, app):
    _sign_in(client, app)
    resp = client.get("/game/999999")
    assert resp.status_code == 404 and "Nothing here" in resp.get_data(as_text=True)


def test_the_device_api_gets_json_not_html(client, app):
    resp = client.get("/api/v1/no-such-endpoint")
    assert resp.status_code == 404 and resp.is_json


def test_the_404_page_offers_sign_in_when_signed_out(client, app):
    body = client.get("/no-such-page").get_data(as_text=True)
    assert 'href="/login"' in body and "Log out" not in body


def test_a_500_is_styled_and_saves_nothing(app):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.route("/__boom")
    def boom():
        raise RuntimeError("synthetic failure")

    resp = app.test_client().get("/__boom")
    assert resp.status_code == 500 and "Something broke" in resp.get_data(as_text=True)


def test_stylesheets_carry_a_content_version(client, app):
    body = client.get("/login").get_data(as_text=True)
    for name in ("tokens", "base", "components"):
        assert re.search(rf'/static/css/{name}\.css\?v=[0-9a-f]{{10}}"', body), name
    assert re.search(r'/static/js/ui\.js\?v=[0-9a-f]{10}"', body)


def test_the_sign_in_page_is_on_the_new_shell(client, app):
    body = client.get("/login").get_data(as_text=True)
    assert "css/components.css" in body and "cyberpunk.css" not in body
    assert 'autocomplete="username"' in body and 'autocomplete="current-password"' in body
    assert "theme-toggle" not in body


def test_no_page_offers_the_retired_light_theme(client, app):
    _sign_in(client, app)
    for path in ("/", "/games"):
        assert "toggleTheme" not in client.get(path).get_data(as_text=True)


def test_the_service_worker_is_versioned_and_network_first():
    sw = open(os.path.join(ROOT, "static", "service-worker.js"), encoding="utf-8").read()
    assert 'CACHE_NAME = "arcade-tracker-v2"' in sw
    assert sw.index("fetch(event.request)") < sw.index("caches.match(event.request)")


def test_the_manifest_names_no_venue():
    manifest = json.load(open(os.path.join(ROOT, "static", "manifest.json")))
    assert manifest["name"] == "Arcade Tracker"
    assert manifest["theme_color"] == "#150a28"
