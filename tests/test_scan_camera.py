"""Scanning a cabinet label with a phone's camera (owner's request, 2026-10-26).

A phone has no USB scanner, so the Scan page offers the camera too. The decoded text goes into
the same box a scanner types into, so `/scan?code=` resolves it exactly as before and printed
labels (`/g/<barcode>`) are untouched. The browser walk with a fake camera is not part of the
suite (it needs Chromium); these keep the pieces it depends on in place.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
JSQR = ROOT / "static" / "js" / "vendor" / "jsQR.js"


@pytest.fixture()
def signed_in(app, client):
    from app.extensions import db
    from app.models import Game, User

    with app.app_context():
        user = User(username="scanner", role="readonly", must_change_password=False)
        user.set_password("not-a-real-password")
        db.session.add_all([user, Game(name="Widget Wars", barcode="widget-wars")])
        db.session.commit()
    client.post("/login", data={"username": "scanner", "password": "not-a-real-password"})
    return client


def test_the_page_offers_the_camera_behind_a_script(signed_in):
    body = signed_in.get("/scan").get_data(as_text=True)
    # Hidden until scan.js shows it, so a browser without scripts sees only the form.
    assert re.search(r'<section[^>]*data-camera[^>]*hidden', body)
    assert "Scan with camera" in body
    assert re.search(r'<script src="/static/js/scan\.js\?v=\w+">', body)
    assert re.search(r'data-jsqr="/static/js/vendor/jsQR\.js\?v=\w+"', body)


def test_the_box_a_usb_scanner_types_into_stays(signed_in):
    body = signed_in.get("/scan").get_data(as_text=True)
    assert 'id="code" name="code"' in body
    assert "data-keep-focus" in body


@pytest.mark.parametrize("read", ["widget-wars", "https://tracker.example.com/g/widget-wars"])
def test_what_the_camera_reads_resolves_like_a_typed_code(signed_in, read):
    resp = signed_in.get("/scan", query_string={"code": read})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/g/widget-wars")


def test_the_decoder_is_served_from_this_site(signed_in):
    resp = signed_in.get("/static/js/vendor/jsQR.js")
    assert resp.status_code == 200
    assert b"jsQR" in resp.data[:400]


def test_the_vendored_decoder_is_the_published_build():
    """static/js/vendor/README.md records the hash; a changed file must change both."""
    digest = hashlib.sha256(JSQR.read_bytes()).hexdigest()
    readme = (JSQR.parent / "README.md").read_text()
    assert digest in readme
    assert (JSQR.parent / "jsQR.LICENSE.txt").read_text().lstrip().startswith("Apache License")


def test_the_scan_script_fetches_nothing_from_elsewhere():
    source = (ROOT / "static" / "js" / "scan.js").read_text()
    assert not re.search(r"https?://\w", source)
