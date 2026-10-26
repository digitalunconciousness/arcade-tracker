"""The arcade's name, logo and sign-in background (owner's request, 2026-10-26).

The logo replaces the wordmark and appears on the sign-in page, the coin-door form, printed
labels and PDFs; SVG is allowed, cleaned on upload and served so that it can't run script.
"""
from __future__ import annotations

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "characterization"))
from char_support import flashes, login
from seed import seed_floor

EVIL_SVG = b"""<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     viewBox="0 0 100 40" onload="alert(1)">
  <script>alert(2)</script>
  <style>@import url(https://evil.example/x.css);</style>
  <defs><linearGradient id="g"><stop offset="0" stop-color="#f0f"/></linearGradient></defs>
  <rect width="100" height="40" fill="url(#g)" onclick="alert(3)"/>
  <rect width="10" height="10" style="fill:url(https://evil.example/leak)"/>
  <use xlink:href="https://evil.example/sprite.svg#x"/>
  <use href="#g"/>
  <a href="javascript:alert(4)"><text>click</text></a>
  <foreignObject><div xmlns="http://www.w3.org/1999/xhtml">html</div></foreignObject>
  <image href="https://evil.example/track.png"/>
  <text x="5" y="30">Comet Arcade</text>
</svg>"""


@pytest.fixture()
def floor(app):
    return seed_floor()


def png(size=(300, 100), mode="RGBA") -> io.BytesIO:
    from PIL import Image

    buf = io.BytesIO()
    Image.new(mode, size, (255, 0, 128, 128) if mode == "RGBA" else (20, 30, 40)).save(buf, "PNG")
    buf.seek(0)
    return buf


def save(client, **data):
    return client.post("/admin/branding", data=data, content_type="multipart/form-data")


@pytest.fixture()
def admin(client, floor):
    login(client, "admin")
    return client


# --- defaults -----------------------------------------------------------------------------------

def test_without_branding_it_is_arcade_tracker(client, floor):
    html = client.get("/login").get_data(as_text=True)
    assert ">CABCRAWL</a>" in html and "<title>Sign in · Cabcrawl</title>" in html
    assert "auth__logo" not in html and "auth__bg" not in html
    assert client.get("/branding/logo").status_code == 404


# --- name ---------------------------------------------------------------------------------------

def test_the_name_goes_in_the_tab_the_header_and_the_coin_door_form(admin, floor, app):
    from app.extensions import db
    from app.models import Game

    save(admin, arcade_name="  Comet   Arcade ")
    html = admin.get("/").get_data(as_text=True)
    assert "<title>Dashboard · Comet Arcade</title>" in html
    assert ">Comet Arcade</a>" in html and ">CABCRAWL</a>" not in html
    assert "Runs on Cabcrawl" in html, "the AGPL credit stays"
    game = db.session.get(Game, floor["raider"])
    token = game.mint_report_token()
    db.session.commit()
    assert "Report a problem · Comet Arcade" in admin.get(f"/report/{token}").get_data(
        as_text=True)


def test_an_over_long_name_is_refused(admin):
    from app.models import Setting

    save(admin, arcade_name="x" * 61)
    assert Setting.get("arcade_name") is None
    assert any("60 characters" in m for _, m in flashes(admin))


# --- a raster logo ------------------------------------------------------------------------------

def test_a_png_logo_shows_everywhere(admin, floor, app):
    from PIL import Image

    from app.extensions import db
    from app.models import Game

    save(admin, logo=(png(), "logo.png"))
    resp = admin.get("/branding/logo")
    assert resp.status_code == 200 and resp.mimetype == "image/png"
    assert Image.open(io.BytesIO(resp.data)).mode == "RGBA", "transparency kept"
    assert 'class="brand__logo"' in admin.get("/").get_data(as_text=True)
    game = db.session.get(Game, floor["raider"])
    token = game.mint_report_token()
    db.session.commit()
    assert "report-page__logo" in admin.get(f"/report/{token}").get_data(as_text=True)
    assert "label-logo" in admin.get(f"/labels/sheet?ids={floor['raider']}").get_data(
        as_text=True)
    admin.post("/logout")
    assert "auth__logo" in client_html(admin, "/login")
    assert admin.get("/branding/logo").status_code == 200, "public: the sign-in page needs it"


def client_html(client, url):
    return client.get(url).get_data(as_text=True)


def test_a_big_logo_is_shrunk(admin, app):
    from PIL import Image

    save(admin, logo=(png((3000, 1000)), "huge.png"))
    img = Image.open(io.BytesIO(admin.get("/branding/logo").data))
    assert max(img.size) == 1024


def test_the_pdfs_carry_the_logo(admin, floor):
    save(admin, logo=(png(), "logo.png"))
    pdf = admin.get(f"/download_maintenance_record/{floor['open_order']}").data
    assert pdf.startswith(b"%PDF") and b"/Subtype /Image" in pdf


def test_without_a_raster_logo_the_pdf_carries_the_name(admin, floor):
    save(admin, arcade_name="Comet Arcade", logo=(io.BytesIO(EVIL_SVG), "logo.svg"))
    pdf = admin.get(f"/download_maintenance_record/{floor['open_order']}").data
    assert pdf.startswith(b"%PDF") and b"/Subtype /Image" not in pdf


@pytest.mark.parametrize(("data", "name", "message"), [
    (b"not an image at all", "logo.png", "couldn't be read"),
    (b"", "logo.png", "Choose a file"),
    (b"x" * (2 * 1024 * 1024 + 1), "logo.png", "over 2 MB"),
])
def test_a_bad_logo_is_refused(admin, data, name, message):
    from app.models import Setting

    save(admin, logo=(io.BytesIO(data), name))
    assert Setting.get("logo_file") is None
    assert any(message in m for _, m in flashes(admin))


def test_removing_the_logo_brings_the_wordmark_back(admin, app):
    from app.services.branding import folder

    save(admin, logo=(png(), "logo.png"))
    save(admin, remove_logo="1")
    assert ">CABCRAWL</a>" in admin.get("/").get_data(as_text=True)
    with app.test_request_context():
        assert not os.path.exists(os.path.join(folder(), "logo.png"))
    assert admin.get("/branding/logo").status_code == 404


# --- SVG ----------------------------------------------------------------------------------------

def test_an_svg_logo_keeps_its_drawing_and_loses_everything_else(admin):
    save(admin, logo=(io.BytesIO(EVIL_SVG), "logo.svg"))
    resp = admin.get("/branding/logo")
    svg = resp.data.decode()
    assert resp.mimetype == "image/svg+xml"
    for gone in ("onload", "onclick", "<script", "alert", "@import", "evil.example",
                 "javascript:", "foreignObject", "<image", "<a ", "<style"):
        assert gone not in svg, gone
    for kept in ("Comet Arcade", 'fill="url(#g)"', "linearGradient", 'href="#g"'):
        assert kept in svg, kept


def test_an_svg_is_served_so_it_cannot_run_script(admin):
    save(admin, logo=(io.BytesIO(EVIL_SVG), "logo.svg"))
    resp = admin.get("/branding/logo")
    policy = resp.headers["Content-Security-Policy"]
    assert "sandbox" in policy and "default-src 'none'" in policy
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(("data", "message"), [
    (b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x "y">]><svg xmlns="http://www.w3.org/2000/svg">&x;</svg>',
     "DOCTYPE"),
    (b'<svg xmlns="http://www.w3.org/2000/svg"><rect', "couldn't be read"),
    (b'<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><svg/></html>',
     "isn't an SVG"),
])
def test_a_bad_svg_is_refused(admin, data, message):
    from app.models import Setting

    save(admin, logo=(io.BytesIO(data), "logo.svg"))
    assert Setting.get("logo_file") is None
    assert any(message in m for _, m in flashes(admin))


# --- the sign-in background ---------------------------------------------------------------------

def test_a_background_goes_behind_the_sign_in_form(admin):
    from PIL import Image

    save(admin, background=(png((4000, 2000), "RGB"), "bg.png"))
    resp = admin.get("/branding/background")
    img = Image.open(io.BytesIO(resp.data))
    assert resp.mimetype == "image/jpeg" and max(img.size) == 2560
    admin.post("/logout")
    html = admin.get("/login").get_data(as_text=True)
    assert 'class="auth__bg"' in html and "auth--over" in html


def test_an_svg_is_not_a_background(admin):
    from app.models import Setting

    save(admin, background=(io.BytesIO(EVIL_SVG), "bg.svg"))
    assert Setting.get("background_file") is None


# --- the logo for printing ----------------------------------------------------------------------

def test_labels_and_pdfs_use_the_print_logo_when_there_is_one(admin, floor):
    save(admin, logo=(png(), "logo.png"))
    sheet = admin.get(f"/labels/sheet?ids={floor['raider']}").get_data(as_text=True)
    assert 'class="label-logo" src="/branding/logo' in sheet
    save(admin, print_logo=(png(mode="RGB"), "print.png"))
    sheet = admin.get(f"/labels/sheet?ids={floor['raider']}").get_data(as_text=True)
    assert 'class="label-logo" src="/branding/print-logo' in sheet
    html = admin.get("/").get_data(as_text=True)
    assert 'class="brand__logo" src="/branding/logo' in html, "the screen keeps the main logo"
    pdf = admin.get(f"/download_maintenance_record/{floor['open_order']}").data
    assert b"/Subtype /Image" in pdf
    save(admin, remove_print_logo="1")
    assert admin.get("/branding/print-logo").status_code == 404

