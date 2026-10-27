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
        user = User(username="tester", role="manager", must_change_password=False)
        user.set_password("not-a-real-password")
        db.session.add(user)
        db.session.commit()
    client.post("/login", data={"username": "tester",
                                "password": "not-a-real-password"},
                follow_redirects=True)
    return client


def _print(client, *ids):
    """Press Print on the picker: POST the selection, follow the redirect to the sheet."""
    return client.post("/labels/coindoor/sheet", data={"ids": ",".join(map(str, ids))},
                       follow_redirects=True)


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
    body = _print(signed_in, floor['Widget Wars']).get_data(
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
    _print(signed_in, floor['Widget Wars'])
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_token is not None


def test_reprinting_does_not_change_the_token(signed_in, floor):
    """The label already inside a door has to keep working."""
    from app.extensions import db
    from app.models import Game

    first = TOKEN_IN_URL.search(
        _print(signed_in, floor["Widget Wars"]).get_data(as_text=True)).group(1)
    second = TOKEN_IN_URL.search(
        _print(signed_in, floor["Widget Wars"]).get_data(as_text=True)).group(1)
    assert first == second
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_token == first


def test_the_sheet_says_how_many_tokens_are_new(signed_in, floor):
    """Minting 98 secrets behind a print button is a decision; the page has to admit to it."""
    body = _print(signed_in, *floor.values()).get_data(as_text=True)
    assert "Made 3 new coin-door codes" in body


def test_a_machine_with_no_barcode_still_gets_a_coin_door_label(signed_in, floor):
    """The token does not depend on the barcode. A machine missing its roster slug is a
    machine the bench cannot identify, which is a different problem from being unreportable."""
    body = _print(signed_in, floor['No Identifier Yet']).get_data(as_text=True)
    assert "No Identifier Yet" in body
    assert TOKEN_IN_URL.search(body)


def test_each_machine_gets_its_own_token(signed_in, floor):
    body = _print(signed_in, *floor.values()).get_data(as_text=True)
    tokens = set(TOKEN_IN_URL.findall(body))
    assert len(tokens) == 3, tokens


def test_the_printed_label_url_actually_opens_the_form(signed_in, floor):
    """The whole point of printing it. A sheet whose QR does not resolve is paper."""
    body = _print(signed_in, floor['Widget Wars']).get_data(
        as_text=True)
    token = TOKEN_IN_URL.search(body).group(1)
    anonymous = signed_in.application.test_client()
    page = anonymous.get(f"/report/{token}")
    assert page.status_code == 200
    assert "Widget Wars" in page.get_data(as_text=True)


# --- the two kinds of label must not converge --------------------------------------------

def test_the_public_sheet_carries_no_report_token(signed_in, floor):
    """The regression that matters. These labels go on the outside of a cabinet."""
    _print(signed_in, *floor.values())          # mint tokens for everything first
    body = signed_in.get("/labels/sheet").get_data(as_text=True)
    assert "/report/" not in body
    assert not TOKEN_IN_URL.search(body)


def test_the_public_single_label_carries_no_report_token(signed_in, floor):
    _print(signed_in, *floor.values())
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
    body = _print(signed_in, floor['Widget Wars']).get_data(
        as_text=True)
    old = TOKEN_IN_URL.search(body).group(1)

    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)

    anonymous = signed_in.application.test_client()
    assert anonymous.get(f"/report/{old}").status_code == 404


def test_the_new_token_works(signed_in, floor):
    from app.extensions import db
    from app.models import Game

    _print(signed_in, floor['Widget Wars'])
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)
    with signed_in.application.app_context():
        new = db.session.get(Game, floor["Widget Wars"]).report_token
    anonymous = signed_in.application.test_client()
    assert anonymous.get(f"/report/{new}").status_code == 200


def test_a_rotated_machine_shows_up_as_needing_a_reprint(signed_in, floor):
    """Otherwise rotating a token quietly makes a machine unreportable: the label is still
    in the door, it still scans, and it leads nowhere."""
    _print(signed_in, floor['Widget Wars'])
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)
    body = signed_in.get("/labels/coindoor").get_data(as_text=True)
    assert "needs a reprint" in body.lower()
    assert "Widget Wars" in body


def test_printing_clears_the_reprint_flag(signed_in, floor):
    from app.extensions import db
    from app.models import Game

    _print(signed_in, floor['Widget Wars'])
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                   follow_redirects=True)
    _print(signed_in, floor['Widget Wars'])
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


# --- Step 4.7a: who may print, and what a page load may change ---------------------------

def _sign_in_as(app, role):
    """A client signed in as a new user with *role*. One per test: the suite's clients
    share a session, so a second sign-in in the same test would not switch users."""
    from app.extensions import db
    from app.models import User

    with app.app_context():
        user = User(username=f"as-{role}", role=role, must_change_password=False)
        user.set_password("not-a-real-password")
        db.session.add(user)
        db.session.commit()
    client = app.test_client()
    client.post("/login", data={"username": f"as-{role}", "password": "not-a-real-password"})
    return client


@pytest.mark.parametrize("role", ["readonly", "operator"])
def test_below_manager_cannot_print_or_retire_coin_door_labels(app, floor, role):
    """F-17: each label is a key, so handing them out is a manager's call."""
    from app.extensions import db
    from app.models import Game

    client = _sign_in_as(app, role)
    assert client.get("/labels/coindoor").status_code == 302
    assert client.get("/labels/coindoor/sheet").status_code == 302
    client.post("/labels/coindoor/sheet", data={"ids": str(floor["Widget Wars"])})
    client.post(f"/game/{floor['Widget Wars']}/report-token/rotate")
    with app.app_context():
        game = db.session.get(Game, floor["Widget Wars"])
        assert game.report_token is None and game.report_label_stale is False


def test_operators_print_machine_labels(app, floor):
    operator = _sign_in_as(app, "operator")
    assert operator.get("/labels").status_code == 200
    assert operator.get(f"/game/{floor['Widget Wars']}/label").status_code == 200


def test_readonly_users_do_not_print_machine_labels(app, floor):
    """Printing the single label can mint a barcode, which is not a read."""
    readonly = _sign_in_as(app, "readonly")
    assert readonly.get("/labels").status_code == 302
    assert readonly.get("/labels/sheet").status_code == 302
    assert readonly.get(f"/game/{floor['Widget Wars']}/label").status_code == 302


def test_opening_the_sheet_changes_nothing(signed_in, floor):
    """F-14: GET only shows labels. A refresh or a prefetch must not mint secrets."""
    from app.extensions import db
    from app.models import Game

    body = signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}").get_data(
        as_text=True)
    assert "no code yet" in body
    assert not TOKEN_IN_URL.search(body)
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_token is None


def test_opening_the_sheet_does_not_clear_the_reprint_flag(signed_in, floor):
    from app.extensions import db
    from app.models import Game

    _print(signed_in, floor["Widget Wars"])
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate")
    signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}")
    with signed_in.application.app_context():
        assert db.session.get(Game, floor["Widget Wars"]).report_label_stale is True


def test_a_post_that_names_no_machines_mints_nothing(signed_in, floor):
    """An empty or truncated form must not mean "every machine on the floor"."""
    from app.models import Game

    signed_in.post("/labels/coindoor/sheet", data={})
    signed_in.post("/labels/coindoor/sheet", data={"ids": ""})
    assert Game.query.filter(Game.report_token.isnot(None)).count() == 0


def test_the_picker_always_sends_an_ids_field(signed_in, floor):
    """So unticking every box selects nothing rather than everything."""
    body = signed_in.get("/labels/coindoor").get_data(as_text=True)
    assert '<input type="hidden" name="ids" value="">' in body


@pytest.mark.parametrize("fmt", ["paper", "avery-22806", "dymo-30334"])
def test_every_format_prints_the_same_codes(signed_in, floor, fmt):
    _print(signed_in, floor["Widget Wars"])
    body = signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}&format={fmt}"
                         ).get_data(as_text=True)
    assert f"sheet--{fmt}" in body
    assert len(TOKEN_IN_URL.findall(body)) >= 1


def test_the_label_printer_puts_one_label_on_each_page(signed_in, floor):
    _print(signed_in, *floor.values())
    body = signed_in.get("/labels/coindoor/sheet?format=dymo-30334").get_data(as_text=True)
    assert body.count('class="sheet sheet--dymo-30334"') == 3


def test_an_unknown_format_falls_back_to_plain_paper(signed_in, floor):
    _print(signed_in, floor["Widget Wars"])
    body = signed_in.get(f"/labels/coindoor/sheet?ids={floor['Widget Wars']}&format=nope"
                         ).get_data(as_text=True)
    assert "sheet--paper" in body


def test_a_lan_address_is_called_out_before_printing(signed_in, floor):
    """The test client is http://localhost/: a sheet printed from here would only ever work
    inside the building, and the page must say so."""
    body = _print(signed_in, floor["Widget Wars"]).get_data(as_text=True)
    assert "will not work from a phone on mobile data" in body


def test_a_public_base_url_gets_no_warning(app, signed_in, floor):
    app.config["BASE_URL"] = "https://tracker.example.com"
    body = _print(signed_in, floor["Widget Wars"]).get_data(as_text=True)
    assert "will not work from a phone" not in body
    assert "https://tracker.example.com/report/" in body


@pytest.mark.parametrize(("url", "bad"), [
    ("http://localhost:5000/report/x", True),
    ("http://10.0.1.20/report/x", True),
    ("http://10.0.0.5/report/x", True),
    ("http://arcade-box/report/x", True),
    ("http://arcade.local/report/x", True),
    ("https://tracker.example.com/report/x", False),
    ("https://203.0.113.7/report/x", True),       # documentation range: not reachable
])
def test_address_problem(url, bad):
    from app.services.labels import address_problem

    assert (address_problem(url) is not None) is bad


def test_retiring_from_the_machine_page_returns_there(signed_in, floor):
    _print(signed_in, floor["Widget Wars"])
    resp = signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate",
                          data={"next": "machine"})
    assert resp.headers["Location"].endswith(f"/game/{floor['Widget Wars']}")


def test_the_machine_page_shows_managers_the_label_state(signed_in, floor):
    body = signed_in.get(f"/game/{floor['Widget Wars']}").get_data(as_text=True)
    assert "Coin-door label" in body and "None yet" in body
    _print(signed_in, floor["Widget Wars"])
    body = signed_in.get(f"/game/{floor['Widget Wars']}").get_data(as_text=True)
    assert "Printed" in body


def test_the_machine_page_hides_the_label_from_operators(app, floor):
    body = _sign_in_as(app, "operator").get(f"/game/{floor['Widget Wars']}").get_data(
        as_text=True)
    assert "Coin-door label" not in body and "report-token" not in body


def test_the_dashboard_names_machines_needing_a_new_label(signed_in, floor):
    _print(signed_in, floor["Widget Wars"])
    signed_in.post(f"/game/{floor['Widget Wars']}/report-token/rotate")
    body = signed_in.get("/").get_data(as_text=True)
    assert "1 coin-door label retired" in body and "Widget Wars" in body


def test_the_machine_list_links_to_the_labels(signed_in, floor):
    assert "/labels" in signed_in.get("/games").get_data(as_text=True)
