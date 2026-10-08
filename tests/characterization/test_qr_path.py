"""The printed-label path: ``/g/<barcode>``. Hard rule: never changes.

Labels on cabinets encode ``<BASE_URL>/g/<Game.barcode>``. Whatever the redesign does to
the page a scan lands on, these must hold:

* the URL shape and the barcode lookup (slug first, numeric id as a fallback);
* an unknown code goes to the scan page with a message, not a 404;
* someone signed out is sent to log in and then **back to the machine** they scanned, which
  is the whole point of scanning from a phone.

Since the machine-page step (4.2) the redirect lands on ``/game/<id>``, which every role can
read (F-16 fixed); it used to land on the operator-only work-order form.
"""
from __future__ import annotations

from urllib.parse import unquote

from char_support import PASSWORD, flashes, login


def test_a_barcode_redirects_to_the_machine(client, floor):
    login(client, "operator")
    resp = client.get("/g/neon-raider")
    assert resp.status_code == 302
    assert resp.headers["Location"] == f"/game/{floor['raider']}"


def test_a_numeric_id_still_resolves(client, floor):
    login(client, "operator")
    resp = client.get(f"/g/{floor['pinball']}")
    assert resp.headers["Location"] == f"/game/{floor['pinball']}"


def test_a_slug_wins_over_a_numeric_id(client, floor):
    """A machine whose barcode is all digits is found by barcode, not by primary key."""
    from app.extensions import db
    from app.models import Game

    db.session.get(Game, floor["courier"]).barcode = str(floor["raider"])
    db.session.commit()
    login(client, "operator")
    resp = client.get(f"/g/{floor['raider']}")
    assert resp.headers["Location"] == f"/game/{floor['courier']}"


def test_an_unknown_code_goes_back_to_the_scanner(client, floor):
    login(client, "operator")
    resp = client.get("/g/no-such-machine")
    assert resp.headers["Location"] == "/scan"
    assert ("error", "No machine found for scanned code 'no-such-machine'.") in flashes(client)


def test_signed_out_scan_logs_in_and_returns_to_the_machine(client, floor):
    resp = client.get("/g/neon-raider")
    assert resp.status_code == 302
    location = unquote(resp.headers["Location"])
    assert location.startswith("/login") and "next=/g/neon-raider" in location

    resp = client.post("/login?next=/g/neon-raider",
                       data={"username": "test-operator", "password": PASSWORD})
    assert resp.headers["Location"] == "/g/neon-raider"
    resp = client.get("/g/neon-raider")
    assert resp.headers["Location"] == f"/game/{floor['raider']}"


def test_labels_encode_the_g_path_with_the_barcode(client, floor, app):
    app.config["BASE_URL"] = "https://tracker.example"
    login(client, "readonly")
    html = client.get(f"/game/{floor['raider']}/label").get_data(as_text=True)
    assert "https://tracker.example/g/neon-raider" in html


def test_the_scan_page_submits_to_the_g_path(client, floor):
    login(client, "readonly")
    html = client.get("/scan").get_data(as_text=True)
    assert "/g/" in html


def test_a_readonly_scan_lands_on_a_page_it_can_read(client, floor):
    """F-16, fixed: readonly sees the machine, not 'permission denied'."""
    login(client, "readonly")
    resp = client.get("/g/neon-raider", follow_redirects=True)
    body = resp.get_data(as_text=True)
    assert resp.status_code == 200 and "Neon Raider" in body
    assert "You do not have permission" not in body
    assert "Joystick drifts left" in body, "the open work order is visible"
    assert "Report a problem" not in body, "readonly cannot file one"


def test_an_operator_scan_offers_the_report_form(client, floor):
    login(client, "operator")
    body = client.get("/g/neon-raider", follow_redirects=True).get_data(as_text=True)
    assert "Report a problem" in body
    assert f'action="/maintenance/game/{floor["raider"]}"' in body
