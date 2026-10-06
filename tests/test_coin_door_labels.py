"""The coin-door label sheet: /labels/coindoor and /labels/coindoor/sheet.

A second kind of label, and the reason it is second rather than an addition to the first.

``_label_url`` builds ``<base>/g/<slug>`` and is shared by the sheet and the single label.
Those are the *public* labels: they go where a tech or the bench scanner can read them, and
the slug in them is meant to be guessable. Putting the coin-door token in that URL -- which
is what the plan for this phase originally said -- would print a credential on the outside
of a cabinet, where any customer could photograph it. So coin-door labels get their own
sheet and their own URL, and a test here holds the two apart.

Every machine in these tests is invented.
"""
from __future__ import annotations

import re

import pytest

TOKEN_IN_URL = re.compile(r"/report/([0-9a-f]{32})")


@pytest.fixture()
def floor(app):
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        rows = [
            Game(name="Widget Wars", barcode="widget-wars", manufacturer="Acme"),
            Game(name="Cogs n Gears", barcode="cogs-n-gears", manufacturer="Acme"),
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


def test_the_picker_needs_a_session(client, floor):
    """Printing these is an inside-the-building job. The labels are credentials."""
    response = client.get("/labels/coindoor", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_the_sheet_needs_a_session(client, floor):
    response = client.get("/labels/coindoor/sheet", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_the_picker_lists_the_floor(signed_in, floor):
    body = signed_in.get("/labels/coindoor").get_data(as_text=True)
    assert "Widget Wars" in body
    assert "Cogs n Gears" in body


def test_the_sheet_encodes_a_report_url(signed_in, floor):
    body = signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}").get_data(
        as_text=True)
    assert TOKEN_IN_URL.search(body), body[:400]


def test_printing_mints_a_token_for_a_machine_that_has_none(signed_in, floor):
    """Unlike the public sheet, which refuses to invent a barcode. A barcode is an identifier
    of record, shared with GATBOX and the roster; a report token is an internal secret, and
    minting it *is* what printing the label means. Refusing would leave no way to ever get a
    first label."""
    from app.extensions import db
    from app.models import Game

    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_token is None
    signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}")
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_token is not None


def test_reprinting_does_not_change_the_token(signed_in, floor):
    """The label already inside a door has to keep working."""
    from app.extensions import db
    from app.models import Game

    path = f"/labels/coindoor/sheet?ids={floor['Widget Wars']}"
    first = TOKEN_IN_URL.search(signed_in.get(path).get_data(as_text=True)).group(1)
    second = TOKEN_IN_URL.search(signed_in.get(path).get_data(as_text=True)).group(1)
    assert first == second
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_token == first


def test_the_sheet_says_how_many_tokens_are_new(signed_in, floor):
    """Minting 98 secrets behind a print button is a decision; the page has to admit to it."""
    body = signed_in.get("/labels/coindoor/sheet").get_data(as_text=True)
    assert "new" in body.lower()


def test_a_machine_with_no_barcode_still_gets_a_coin_door_label(signed_in, floor):
    """The token does not depend on the barcode. A machine missing its roster slug is a
    machine the bench cannot identify, which is a different problem from being unreportable."""
    body = signed_in.get(
        f"/labels/coindoor/sheet?ids={floor['No Identifier Yet']}").get_data(as_text=True)
    assert "No Identifier Yet" in body
    assert TOKEN_IN_URL.search(body)


def test_each_machine_gets_its_own_token(signed_in, floor):
    body = signed_in.get("/labels/coindoor/sheet").get_data(as_text=True)
    tokens = set(TOKEN_IN_URL.findall(body))
    assert len(tokens) == 3, tokens


def test_the_printed_label_url_actually_opens_the_form(signed_in, floor):
    """The whole point of printing it. A sheet whose QR does not resolve is paper."""
    body = signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}").get_data(
        as_text=True)
    token = TOKEN_IN_URL.search(body).group(1)
    anonymous = signed_in.application.test_client()
    page = anonymous.get(f"/report/{token}")
    assert page.status_code == 200
    assert "Widget Wars" in page.get_data(as_text=True)


# --- the two kinds of label must not converge --------------------------------------------

def test_the_public_sheet_carries_no_report_token(signed_in, floor):
    """The regression that matters. These labels go on the outside of a cabinet."""
    signed_in.get("/labels/coindoor/sheet")          # mint tokens for everything first
    body = signed_in.get("/labels/sheet").get_data(as_text=True)
    assert "/report/" not in body
    assert not TOKEN_IN_URL.search(body)


def test_the_public_single_label_carries_no_report_token(signed_in, floor):
    signed_in.get("/labels/coindoor/sheet")
    body = signed_in.get(f"/game/{floor['Widget Wars']}/label").get_data(as_text=True)
    assert "/report/" not in body


def test_the_label_url_helper_is_unchanged(app, floor):
    """Asserted on the helper, because it is the one definition the public sheet and the
    single label share -- and a token appearing in it would be invisible until someone
    scanned a cabinet."""
    from app.extensions import db
    from app.models import Game
    from app.routes.games import _label_url

    with app.test_request_context():
        game = db.session.get(Game, floor["Widget Wars"])
        game.mint_report_token()
        url = _label_url(game)
    assert url.endswith("/g/widget-wars"), url
    assert "/report/" not in url


# --- rotation, for when a label is photographed ------------------------------------------

def test_rotating_needs_a_session(client, floor):
    response = client.post(
        f"/game/{floor['Widget Wars']}/report-token/rotate", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers.get("Location", "")


def test_rotating_is_not_a_get(signed_in, floor):
    """A link that invalidates a physical label must not be followable by a crawler, a
    prefetch, or a mistyped URL."""
    assert signed_in.get(
        f"/game/{floor['Widget Wars']}/report-token/rotate").status_code == 405


def test_rotating_retires_the_printed_label(signed_in, floor):
    """The remedy when a label has been photographed: the QR in the door stops working."""
    body = signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}").get_data(
        as_text=True)
    old = TOKEN_IN_URL.search(body).group(1)

    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)

    anonymous = signed_in.application.test_client()
    assert anonymous.get(f"/report/{old}").status_code == 404


def test_the_new_token_works(signed_in, floor):
    from app.extensions import db
    from app.models import Game

    signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}")
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)
    with signed_in.application.app_context():
        new = db.session.get(Game, floor["Widget Wars"]).report_token
    anonymous = signed_in.application.test_client()
    assert anonymous.get(f"/report/{new}").status_code == 200


def test_a_rotated_machine_shows_up_as_needing_a_reprint(signed_in, floor):
    """Otherwise rotating a token quietly makes a machine unreportable: the label is still
    in the door, it still scans, and it leads nowhere."""
    signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}")
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)
    body = signed_in.get("/labels/coindoor").get_data(as_text=True)
    assert "needs a reprint" in body.lower()
    assert "Widget Wars" in body


def test_printing_clears_the_reprint_flag(signed_in, floor):
    from app.extensions import db
    from app.models import Game

    signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}")
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)
    signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}")
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_label_stale is False


def test_rotating_an_unknown_machine_is_not_found(signed_in, floor):
    assert signed_in.post("/game/99999/report-token/rotate").status_code == 404


def test_rotating_does_not_touch_the_public_label(signed_in, floor):
    """The barcode is the identifier of record. Rotating a secret must not renumber a machine."""
    from app.extensions import db
    from app.models import Game

    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).barcode == "widget-wars"
