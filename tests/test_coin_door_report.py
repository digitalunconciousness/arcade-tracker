"""``/report/<token>``: filing a maintenance request with no login.

Phase 2.5. The authorisation is physical — you had to open the coin door to read the QR.
That makes this the only anonymous write endpoint in either repo, on a site published to
the internet through a Cloudflare tunnel, so most of what is asserted here is
**containment**: the page exists to create one record for one machine and offers no way
to reach anything else.

What it honestly authorises is "someone who has seen inside this coin door, or anyone
they told". A photographed label is a shared credential; per-machine tokens and easy
rotation are the mitigation, not prevention.

Every machine in these tests is invented.
"""
from __future__ import annotations

import re

import pytest

# Every href the page emits, so the containment claim can be checked rather than asserted.
HREF = re.compile(r'href="([^"]*)"')
ACTION = re.compile(r'action="([^"]*)"')


@pytest.fixture()
def machine(app):
    """One machine with a coin-door token, and one without."""
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        widget = Game(name="Widget Wars", barcode="widget-wars")
        db.session.add_all([widget, Game(name="Cogs n Gears", barcode="cogs-n-gears")])
        db.session.commit()
        token = widget.mint_report_token()
        db.session.commit()
        return {"token": token, "id": widget.id, "name": widget.name}


def test_the_form_answers_without_a_session(client, machine):
    response = client.get(f"/report/{machine['token']}")
    assert response.status_code == 200, response.status_code


def test_it_does_not_redirect_to_the_login_page(client, machine):
    """A login redirect would make the whole feature pointless."""
    response = client.get(f"/report/{machine['token']}", follow_redirects=False)
    assert response.status_code != 302, response.headers.get("Location")


def test_it_names_the_machine(client, machine):
    """Which is on the cabinet anyway -- it is how someone knows they scanned the right one."""
    body = client.get(f"/report/{machine['token']}").get_data(as_text=True)
    assert machine["name"] in body


def test_an_unknown_token_is_not_found(client, machine):
    assert client.get("/report/" + "f" * 32).status_code == 404


def test_a_guessable_slug_is_not_a_token(client, machine):
    """The barcode is public. It must not open this page."""
    assert client.get("/report/widget-wars").status_code == 404


def test_it_names_no_other_machine(client, machine):
    body = client.get(f"/report/{machine['token']}").get_data(as_text=True)
    assert "Cogs n Gears" not in body


def test_the_page_links_to_nothing_but_itself(client, machine):
    """Containment. There is no session to escape with, so there is also nothing to click."""
    path = f"/report/{machine['token']}"
    body = client.get(path).get_data(as_text=True)
    for href in HREF.findall(body):
        assert href.startswith("/static/") or href in ("", "#", path), href
    for action in ACTION.findall(body):
        assert action in ("", path), action


def test_it_grants_no_identity(client, machine):
    """CSRF needs a Flask session cookie, so "issues no cookie" is not the claim.
    "Issues no logged-in identity" is, and that is what has to hold."""
    response = client.get(f"/report/{machine['token']}")
    cookies = response.headers.getlist("Set-Cookie")
    assert not any("remember_token" in c for c in cookies), cookies


def test_the_rest_of_the_site_is_still_shut(client, machine):
    """The same client, straight after loading the form."""
    client.get(f"/report/{machine['token']}")
    for shut in ("/maintenance_orders", "/dashboard", "/games", "/labels"):
        response = client.get(shut, follow_redirects=False)
        assert response.status_code in (302, 401, 403, 404), f"{shut}: {response.status_code}"
        if response.status_code == 302:
            assert "/login" in response.headers.get("Location", "")


def test_it_counts_the_reports_already_open(client, machine):
    """So someone does not file a fifth report for a machine already known to be down.

    "Open" and "In_Progress" both count, because that is what every other page in this
    application means by open -- a machine someone is already working on is not a machine
    that needs reporting again. A closed one does not count.
    """
    from app.extensions import db
    from app.models import MaintenanceRecord

    with client.application.app_context():
        db.session.add_all([
            MaintenanceRecord(game_id=machine["id"],
                              issue_description="Left flipper weak", status="Open"),
            MaintenanceRecord(game_id=machine["id"],
                              issue_description="Coin door sticks", status="In_Progress"),
            MaintenanceRecord(game_id=machine["id"],
                              issue_description="Fixed last week", status="Closed"),
        ])
        db.session.commit()
    body = client.get(f"/report/{machine['token']}").get_data(as_text=True)
    assert "2 reports already open" in body, body[-600:]


def test_the_count_reads_nothing_back_out(client, machine):
    """A count, not a list. This page is create-only: no fault history, no other machine,
    nothing to read -- so there is nothing worth stealing a label for."""
    from app.extensions import db
    from app.models import MaintenanceRecord

    with client.application.app_context():
        db.session.add(MaintenanceRecord(
            game_id=machine["id"], issue_description="Left flipper weak", status="Open"))
        db.session.commit()
    body = client.get(f"/report/{machine['token']}").get_data(as_text=True)
    assert "Left flipper weak" not in body


def test_one_open_report_is_not_pluralised(client, machine):
    from app.extensions import db
    from app.models import MaintenanceRecord

    with client.application.app_context():
        db.session.add(MaintenanceRecord(
            game_id=machine["id"], issue_description="Left flipper weak", status="Open"))
        db.session.commit()
    body = client.get(f"/report/{machine['token']}").get_data(as_text=True)
    assert "1 report already open" in body


def test_no_open_reports_says_so(client, machine):
    body = client.get(f"/report/{machine['token']}").get_data(as_text=True)
    assert "nothing reported" in body.lower()


# --- filing one -------------------------------------------------------------------------

def _records(app):
    from app.models import MaintenanceRecord
    with app.app_context():
        return MaintenanceRecord.query.all()


def test_filing_creates_one_record_for_that_machine(client, machine):
    response = client.post(f"/report/{machine['token']}",
                           data={"issue_description": "Right flipper is dead"},
                           follow_redirects=True)
    assert response.status_code == 200
    rows = _records(client.application)
    assert len(rows) == 1
    assert rows[0].game_id == machine["id"]
    assert rows[0].issue_description == "Right flipper is dead"


def test_the_record_says_where_it_came_from(client, machine):
    """source is what tells a tech this was filed by whoever was standing at the machine,
    with no account behind it. Phase 2 added the column; this is its second writer."""
    client.post(f"/report/{machine['token']}",
                data={"issue_description": "Right flipper is dead"})
    assert _records(client.application)[0].source == "coindoor"


def test_a_filed_report_is_open(client, machine):
    client.post(f"/report/{machine['token']}",
                data={"issue_description": "Right flipper is dead"})
    assert _records(client.application)[0].status == "Open"


def test_the_timestamp_helper_returns_naive_utc(app):
    """The contract, asserted on the function rather than through a round trip.

    MaintenanceRecord.date_reported is TIMESTAMP WITHOUT TIME ZONE, and the model default
    hands it an *aware* datetime -- psycopg2 then converts to the session's zone and drops
    the offset, so 13:00 UTC is stored as 08:00 and labelled UTC. Phase 2 shipped that bug
    on the API path and fixed it there. The suite runs on SQLite, which does no conversion
    at all, so a round-trip test passes either way and proves nothing.
    """
    from datetime import datetime, timezone
    from app.routes.report import _utc_now

    now = _utc_now()
    assert now.tzinfo is None
    assert abs((now - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds()) < 5


def test_the_stored_timestamp_is_naive(client, machine):
    client.post(f"/report/{machine['token']}",
                data={"issue_description": "Right flipper is dead"})
    assert _records(client.application)[0].date_reported.tzinfo is None


def test_an_empty_description_files_nothing(client, machine):
    response = client.post(f"/report/{machine['token']}",
                           data={"issue_description": "   "}, follow_redirects=True)
    assert response.status_code == 200
    assert _records(client.application) == []
    assert "describe the problem" in response.get_data(as_text=True).lower()


def test_a_missing_description_files_nothing(client, machine):
    client.post(f"/report/{machine['token']}", data={}, follow_redirects=True)
    assert _records(client.application) == []


def test_an_over_long_description_is_refused(client, machine):
    """maxlength on the textarea is a hint to a browser, not a control. This endpoint is
    reachable from the internet with curl."""
    response = client.post(f"/report/{machine['token']}",
                           data={"issue_description": "x" * 10_000},
                           follow_redirects=True)
    assert response.status_code == 200
    assert _records(client.application) == []
    assert "too long" in response.get_data(as_text=True).lower()


def test_a_description_at_the_limit_is_accepted(client, machine):
    client.post(f"/report/{machine['token']}", data={"issue_description": "x" * 2000})
    assert len(_records(client.application)) == 1


def test_an_unknown_token_files_nothing(client, machine):
    assert client.post("/report/" + "f" * 32,
                       data={"issue_description": "Right flipper is dead"}).status_code == 404
    assert _records(client.application) == []


def test_the_confirmation_reveals_no_record_id(client, machine):
    """Nothing to look up afterwards, so there is nothing to enumerate."""
    body = client.post(f"/report/{machine['token']}",
                       data={"issue_description": "Right flipper is dead"},
                       follow_redirects=True).get_data(as_text=True)
    record_id = _records(client.application)[0].id
    assert f"#{record_id}" not in body
    assert "thank" in body.lower()


# --- CSRF, and why the token in the URL is the real authorisation -----------------------

def test_the_form_carries_a_csrf_token(client, machine):
    """CSRF is enforced app-wide (since 2026-10-08), so the form must serve a token: a phone
    that scanned the label GETs the form, which sets the session cookie and the token, and
    POSTs both back. tests/characterization/test_csrf.py checks every form the same way.
    """
    body = client.get(f"/report/{machine['token']}").get_data(as_text=True)
    assert 'name="csrf_token"' in body


def test_a_client_with_no_session_at_all_can_file(client, machine):
    """The design, stated as a test: the token in the URL is the authorisation, and it is a
    capability rather than an ambient credential.

    That is also why CSRF adds nothing *here* specifically. A cross-site POST can only reach
    this endpoint if it already knows the token, and anything that knows the token can post
    directly. The control against abuse is the per-token rate limit, not a CSRF check.
    """
    from app.models import MaintenanceRecord

    fresh = client.application.test_client()          # never issued a GET, so holds no cookie
    response = fresh.post(f"/report/{machine['token']}",
                          data={"issue_description": "Right flipper is dead"})
    assert response.status_code in (200, 302), response.status_code
    with client.application.app_context():
        assert MaintenanceRecord.query.count() == 1


@pytest.fixture()
def strict_csrf_app(_isolate_environment):
    """The application as it would be with CSRF actually enforced."""
    from app import create_app
    from app.extensions import db

    application = create_app()
    application.config.update(TESTING=True, WTF_CSRF_ENABLED=True,
                              WTF_CSRF_CHECK_DEFAULT=True)
    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


def _machine_in(application):
    from app.extensions import db
    from app.models import Game

    with application.app_context():
        game = Game(name="Widget Wars", barcode="widget-wars")
        db.session.add(game)
        db.session.commit()
        token = game.mint_report_token()
        db.session.commit()
        return token


def test_the_form_works_with_csrf_enforced(strict_csrf_app):
    """CSRF is on in production; a scanned label must still file a report."""
    import re

    from app.models import MaintenanceRecord

    token = _machine_in(strict_csrf_app)
    client = strict_csrf_app.test_client()
    body = client.get(f"/report/{token}").get_data(as_text=True)
    csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', body)
    assert csrf, "the form serves no csrf token to send back"
    response = client.post(f"/report/{token}",
                           data={"issue_description": "Right flipper is dead",
                                 "csrf_token": csrf.group(1)})
    assert response.status_code in (200, 302), response.status_code
    with strict_csrf_app.app_context():
        assert MaintenanceRecord.query.count() == 1


def test_under_enforcement_a_post_without_a_session_still_files(strict_csrf_app):
    """The blueprint is CSRF-exempt by design (see app/routes/report.py)."""
    from app.models import MaintenanceRecord

    token = _machine_in(strict_csrf_app)
    fresh = strict_csrf_app.test_client()
    response = fresh.post(f"/report/{token}", data={"issue_description": "Coin door jammed"})
    assert response.status_code in (200, 302), response.status_code
    with strict_csrf_app.app_context():
        assert MaintenanceRecord.query.count() == 1


# --- abuse ------------------------------------------------------------------------------

def test_the_sixth_report_for_one_machine_is_refused(client, machine):
    """Five an hour per machine. A coin door is not opened often, and this endpoint is
    anonymous and reachable from the internet."""
    from app.models import MaintenanceRecord

    for n in range(5):
        response = client.post(f"/report/{machine['token']}",
                               data={"issue_description": f"Fault {n}"})
        assert response.status_code in (200, 302), f"report {n}: {response.status_code}"
    assert client.post(f"/report/{machine['token']}",
                       data={"issue_description": "Fault 6"}).status_code == 429
    with client.application.app_context():
        assert MaintenanceRecord.query.count() == 5


def test_reading_the_form_is_not_rationed(client, machine):
    """Only filing is. Someone re-reading the page, or scanning the label twice because the
    first did not focus, must not use up the machine's budget."""
    for _ in range(10):
        assert client.get(f"/report/{machine['token']}").status_code == 200


def test_one_machine_running_out_does_not_block_another(client, machine):
    """The limit is per machine. A busy night on one cabinet must not silence the floor."""
    from app.extensions import db
    from app.models import Game

    with client.application.app_context():
        other = Game.query.filter_by(barcode="cogs-n-gears").one()
        other_token = other.mint_report_token()
        db.session.commit()

    for n in range(6):
        client.post(f"/report/{machine['token']}", data={"issue_description": f"Fault {n}"})
    response = client.post(f"/report/{other_token}",
                           data={"issue_description": "Different machine"})
    assert response.status_code in (200, 302), response.status_code


def test_hitting_the_limit_is_logged_without_the_token(client, machine, caplog):
    """The token is a credential. It is the one thing that must not reach a log line, since
    a log is the place a credential outlives the person who typed it."""
    import logging

    for n in range(5):
        client.post(f"/report/{machine['token']}", data={"issue_description": f"Fault {n}"})
    with caplog.at_level(logging.INFO):
        assert client.post(f"/report/{machine['token']}",
                           data={"issue_description": "Fault 6"}).status_code == 429
    logged = caplog.text
    assert "COINDOOR_RATE_LIMITED" in logged, logged
    assert machine["name"] in logged, "the machine has to be identifiable from the log"
    assert machine["token"] not in logged, "the token reached a log line"


def test_the_form_tells_the_browser_to_send_no_referrer(client, machine):
    """The token is in the URL, so any request the page makes off-origin would carry it in
    the Referer header."""
    response = client.get(f"/report/{machine['token']}")
    assert response.headers.get("Referrer-Policy") == "no-referrer"


def test_every_page_says_no_referrer(client):
    """Set once, for the whole application, rather than on the one blueprint that needs it:
    a header that only some responses carry is a header someone will forget."""
    assert client.get("/login").headers.get("Referrer-Policy") == "no-referrer"
