"""The label sheet: /labels (pick) and /labels/sheet (print).

Printing one label per page is a chore people skip, and a machine whose label is
missing or stale is a machine neither the scan kiosk nor GATBOX can identify. So the
sheet exists to make the whole floor printable in one pass.

What matters here is that it encodes exactly the same URL as the single-label page --
a sheet whose QR codes differ from their neighbours' is not something you discover
until you are standing at a cabinet with a scanner -- and that it never invents an
identifier for a machine that lacks one.

Every machine in these tests is invented.
"""
from __future__ import annotations

import re

import pytest


@pytest.fixture()
def floor(app):
    """Three machines with IDs and one without."""
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        rows = [
            Game(name="Widget Wars", barcode="widget-wars", manufacturer="Acme"),
            Game(name="Cogs n Gears", barcode="cogs-n-gears", manufacturer="Acme"),
            Game(name="Sprocket", barcode="pin-sprocket", manufacturer="Bell"),
            Game(name="No Identifier Yet", barcode=None),
        ]
        db.session.add_all(rows)
        db.session.commit()
        return {g.name: g.id for g in Game.query.all()}


@pytest.fixture()
def signed_in(app, client):
    from app.extensions import db
    from app.models import User

    with app.app_context():
        user = User(username="tester", role="manager")
        user.set_password("not-a-real-password")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "tester",
                                "password": "not-a-real-password"},
                follow_redirects=True)
    return client


# --- it is not open to the world -------------------------------------------

@pytest.mark.parametrize("path", ["/labels", "/labels/sheet"])
def test_both_pages_need_a_session(client, path):
    response = client.get(path)
    assert response.status_code in (301, 302, 401, 403)
    if response.status_code in (301, 302):
        assert "/login" in response.headers["Location"]


# --- the sheet ------------------------------------------------------------

def test_the_sheet_shows_every_machine_that_has_an_id(signed_in, floor):
    body = signed_in.get("/labels/sheet").get_data(as_text=True)
    for name in ("Widget Wars", "Cogs n Gears", "Sprocket"):
        assert name in body
    assert body.count("label-card") >= 3


def test_a_machine_without_an_id_is_skipped_and_named(signed_in, floor):
    """Never mint an identifier behind a print button, 29 at a time."""
    body = signed_in.get("/labels/sheet").get_data(as_text=True)
    assert "No Identifier Yet" in body
    assert "no ID" in body
    from app.models import Game
    # and nothing was written to it
    assert Game.query.filter_by(name="No Identifier Yet").one().barcode is None


def test_the_qr_encodes_the_same_url_as_the_single_label_page(signed_in, floor):
    """One builder, so a sheet label and its own page cannot disagree.

    A QR SVG holds modules, not text, so this does not read the URL back out of the
    image. It takes the URL the single-label page displays, regenerates the QR from it
    exactly as the sheet does, and asserts that image is on the sheet. If the sheet ever
    encoded a different URL, the bytes would not match.
    """
    import html as html_mod

    import segno

    game_id = floor["Widget Wars"]
    single = signed_in.get(f"/game/{game_id}/label").get_data(as_text=True)
    found = re.search(r"<code>(https?://[^<]+/g/widget-wars)</code>", single)
    assert found, "the single label page should show the encoded link"
    url = html_mod.unescape(found.group(1))

    expected = segno.make(url, error="m").svg_data_uri(scale=4, border=2)
    sheet = html_mod.unescape(signed_in.get("/labels/sheet").get_data(as_text=True))
    assert expected in sheet, f"the sheet's QR is not the one built from {url}"


def test_a_different_url_would_not_match(signed_in, floor):
    """Proof the test above can fail: the same machine, a different base URL."""
    import segno

    wrong = segno.make("https://somewhere.else.test/g/widget-wars",
                       error="m").svg_data_uri(scale=4, border=2)
    assert wrong not in signed_in.get("/labels/sheet").get_data(as_text=True)


# --- choosing machines ----------------------------------------------------

def test_repeated_ids_from_the_picker_all_arrive(signed_in, floor):
    """The picker submits ?ids=1&ids=2. Reading only the first printed one label
    when twenty-nine were asked for."""
    qs = f"?ids={floor['Widget Wars']}&ids={floor['Sprocket']}"
    body = signed_in.get("/labels/sheet" + qs).get_data(as_text=True)
    assert "Widget Wars" in body and "Sprocket" in body
    assert "Cogs n Gears" not in body


def test_comma_separated_ids_also_work(signed_in, floor):
    """What a hand-written link, or one built from the reprint list, looks like."""
    qs = f"?ids={floor['Widget Wars']},{floor['Sprocket']}"
    body = signed_in.get("/labels/sheet" + qs).get_data(as_text=True)
    assert "Widget Wars" in body and "Sprocket" in body
    assert "Cogs n Gears" not in body


def test_a_malformed_link_is_refused_not_guessed(signed_in, floor):
    response = signed_in.get("/labels/sheet?ids=widget-wars", follow_redirects=True)
    assert "malformed" in response.get_data(as_text=True)


def test_selecting_nothing_says_so(signed_in, floor):
    response = signed_in.get("/labels/sheet?ids=", follow_redirects=True)
    assert "No machines selected" in response.get_data(as_text=True)


def test_selecting_only_a_machine_without_an_id_prints_nothing(signed_in, floor):
    response = signed_in.get(f"/labels/sheet?ids={floor['No Identifier Yet']}",
                             follow_redirects=True)
    body = response.get_data(as_text=True)
    assert "nothing to print" in body
    assert "roster slug" in body


# --- the picker -----------------------------------------------------------

def test_the_picker_lists_everything_and_ticks_only_what_can_print(signed_in, floor):
    body = signed_in.get("/labels").get_data(as_text=True)
    for name in ("Widget Wars", "Cogs n Gears", "Sprocket", "No Identifier Yet"):
        assert name in body
    # Three checkboxes, pre-ticked; the one without an ID gets none. Count the inputs
    # themselves -- a bare count of "checked" also catches the "checked = true" in the
    # select-all handler, which is how the first version of this test was wrong.
    assert body.count('class="pick"') == 3
    assert len(re.findall(r'class="pick"[^>]*\schecked', body)) == 3
    assert "no ID — set one" in body
