"""Fixes from the security review (2026-10-25). Each test fails on the code before the fix,
except section 2's, which guard behaviour that was already right (see there)."""
from __future__ import annotations

import io
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import PASSWORD, flashes, login
from seed import seed_floor


@pytest.fixture()
def floor(app):
    return seed_floor()


# --- 1. the login page's next= goes nowhere but this site ---------------------------------------

@pytest.mark.parametrize("target", [
    "/\\evil.example", "/\\/evil.example", "/\t/evil.example", "/\n/evil.example",
    "//evil.example", "https://evil.example/", "javascript:alert(1)", "evil.example",
])
def test_next_never_leaves_the_site(client, floor, target):
    resp = client.post("/login", query_string={"next": target},
                       data={"username": "test-operator", "password": PASSWORD})
    assert resp.status_code == 302
    assert "evil" not in resp.headers["Location"] and "javascript" not in resp.headers["Location"]


@pytest.mark.parametrize("target", ["/inventory/", "/game/1?tab=history", "/reports#top"])
def test_next_still_goes_to_a_page_here(client, floor, target):
    resp = client.post("/login", query_string={"next": target},
                       data={"username": "test-operator", "password": PASSWORD})
    assert resp.headers["Location"] == target


# --- 2. deactivating an account ends its session ------------------------------------------------
# This already held: Flask-Login's UserMixin.is_authenticated returns is_active. The user loader
# now refuses an inactive account too, so it holds even if User overrides is_authenticated.

def test_a_deactivated_user_is_signed_out_on_the_next_request(client, floor):
    from app.extensions import db
    from app.models import User

    login(client, "operator")
    assert client.get("/inventory/").status_code == 200
    db.session.get(User, floor["users"]["operator"]).is_active = False
    db.session.commit()
    resp = client.get("/inventory/")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


def test_the_admin_toggle_does_it_too(app, floor):
    from flask import g

    def as_new_request():
        g.pop("_login_user", None)    # the test's app context outlives requests; a server's doesn't

    operator, admin = app.test_client(), app.test_client()
    login(operator, "operator")
    as_new_request()
    login(admin, "admin")
    admin.post("/admin/users", data={"action": "toggle_active",
                                     "user_id": floor["users"]["operator"]})
    as_new_request()
    assert "/login" in operator.get("/inventory/").headers.get("Location", "")


# --- 3. an unknown role grants nothing ----------------------------------------------------------

def test_an_unknown_role_is_never_granted(floor):
    from app.models import User

    admin = User.query.filter_by(username="test-admin").one()
    assert admin.has_role("admin")
    assert not admin.has_role("admni")
    assert not admin.has_role("")


def test_requires_role_refuses_a_typo_when_the_route_is_defined():
    from app.utils.decorators import requires_role

    with pytest.raises(ValueError, match="admni"):
        requires_role("admni")


# --- 4. an oversized image is refused before it is decoded --------------------------------------

def _png(width, height):
    from PIL import Image

    buf = io.BytesIO()
    Image.new("L", (width, height)).save(buf, "PNG")
    buf.seek(0)
    return buf


def test_an_image_over_the_pixel_cap_is_refused(tmp_path, monkeypatch):
    from app.utils import helpers

    monkeypatch.setattr(helpers, "MAX_UPLOAD_PIXELS", 10_000)
    assert helpers.compress_and_save_image(_png(100, 100), str(tmp_path / "ok.jpg"))
    assert not helpers.compress_and_save_image(_png(101, 100), str(tmp_path / "big.jpg"))
    assert not (tmp_path / "big.jpg").exists()


def test_the_cap_still_takes_a_48_megapixel_phone_photo():
    from app.utils.helpers import MAX_UPLOAD_PIXELS

    assert 8064 * 6048 <= MAX_UPLOAD_PIXELS < 200_000_000


# --- 5. error text stays in the log -------------------------------------------------------------

def test_a_chart_error_is_logged_not_parsed_into_the_pdf(client, floor, monkeypatch, caplog):
    """The exception's text went into a ReportLab Paragraph, which parses markup: "<" broke it."""
    import matplotlib.pyplot as plt

    def broken(*args, **kwargs):
        raise ValueError("<font name='x'>& no close")

    monkeypatch.setattr(plt, "figure", broken)
    monkeypatch.setattr(plt, "pie", broken)
    login(client, "manager")
    with caplog.at_level(logging.ERROR):
        resp = client.get("/export_report")
    assert resp.status_code == 200 and resp.mimetype == "application/pdf"
    assert any("failed" in r.getMessage() for r in caplog.records)


def test_a_tracking_error_shows_a_plain_message(client, app, floor, monkeypatch):
    from app.extensions import db
    from app.models import InventoryRequest
    from app.services import inventory as inv

    db.session.get(InventoryRequest, floor["request"]).tracking_number = "1Z999"
    db.session.commit()
    app.config["EASYPOST_API_KEY"] = "test-key"

    def broken(*args, **kwargs):
        raise RuntimeError("carrier said: api_key=test-key is invalid")

    monkeypatch.setattr(inv, "refresh_tracking", broken)
    login(client, "manager")
    client.post(f"/inventory/requests/{floor['request']}/update_tracking")
    messages = " ".join(m for _, m in flashes(client))
    assert "Could not fetch tracking" in messages and "test-key" not in messages
