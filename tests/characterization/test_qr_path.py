"""The printed-label path: ``/g/<barcode>``. Hard rule: never changes.

Labels on cabinets encode ``<BASE_URL>/g/<Game.barcode>``. Whatever the redesign does to
the page a scan lands on, these must hold:

* the URL shape and the barcode lookup (slug first, numeric id as a fallback);
* an unknown code goes to the scan page with a message, not a 404;
* someone signed out is sent to log in and then **back to the machine** they scanned, which
  is the whole point of scanning from a phone.

What a readonly user sees after the redirect is F-16 (test_flags.py).
"""
from __future__ import annotations

from urllib.parse import unquote

from char_support import PASSWORD, flashes, login


def test_a_barcode_redirects_to_the_machine(client, floor):
    login(client, "operator")
    resp = client.get("/g/neon-raider")
    assert resp.status_code == 302
    assert resp.headers["Location"] == f"/maintenance/game/{floor['raider']}"


def test_a_numeric_id_still_resolves(client, floor):
    login(client, "operator")
    resp = client.get(f"/g/{floor['pinball']}")
    assert resp.headers["Location"] == f"/maintenance/game/{floor['pinball']}"


def test_a_slug_wins_over_a_numeric_id(client, floor):
    """A machine whose barcode is all digits is found by barcode, not by primary key."""
    from app.extensions import db
    from app.models import Game

    db.session.get(Game, floor["courier"]).barcode = str(floor["raider"])
    db.session.commit()
    login(client, "operator")
    resp = client.get(f"/g/{floor['raider']}")
    assert resp.headers["Location"] == f"/maintenance/game/{floor['courier']}"


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
    assert resp.headers["Location"] == f"/maintenance/game/{floor['raider']}"


def test_labels_encode_the_g_path_with_the_barcode(client, floor, app):
    app.config["BASE_URL"] = "https://tracker.example"
    login(client, "readonly")
    html = client.get(f"/game/{floor['raider']}/label").get_data(as_text=True)
    assert "https://tracker.example/g/neon-raider" in html


def test_the_scan_page_submits_to_the_g_path(client, floor):
    login(client, "readonly")
    html = client.get("/scan").get_data(as_text=True)
    assert "/g/" in html
