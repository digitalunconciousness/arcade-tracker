"""``Game.report_token``: the secret a coin-door label carries.

Phase 2.5. A maintenance request can be filed with no login by anyone who can open the
coin door, and possession of this token is what stands in for the physical key.

It is deliberately **not** ``barcode``. ``barcode`` is the public identifier: it is the
roster slug, it is printed on the cabinet labels, it is shared with GATBOX, and the slugs
are guessable (``galaga``, ``tmnt``, ``pin-batman``). A site published to the internet
through a Cloudflare tunnel cannot use a guessable value to authorise a write.

Every machine in these tests is invented.
"""
from __future__ import annotations

import re

import pytest

HEX32 = re.compile(r"\A[0-9a-f]{32}\Z")


@pytest.fixture()
def game(app):
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        row = Game(name="Widget Wars", barcode="widget-wars")
        db.session.add(row)
        db.session.commit()
        return row.id


def test_minting_gives_32_hex_characters(app, game):
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        token = db.session.get(Game, game).mint_report_token()
        assert HEX32.match(token), token


def test_minting_twice_keeps_the_first_token(app, game):
    """Printing a second sheet must not invalidate the label already inside the door."""
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        row = db.session.get(Game, game)
        first = row.mint_report_token()
        assert row.mint_report_token() == first


def test_two_machines_never_share_a_token(app, game):
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        other = Game(name="Cogs n Gears", barcode="cogs-n-gears")
        db.session.add(other)
        db.session.commit()
        assert db.session.get(Game, game).mint_report_token() != other.mint_report_token()


def test_the_token_is_never_the_barcode(app, game):
    """The whole point: the public identifier must not authorise anything."""
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        row = db.session.get(Game, game)
        assert row.mint_report_token() != row.barcode


def test_a_token_resolves_to_its_machine(app, game):
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        row = db.session.get(Game, game)
        token = row.mint_report_token()
        assert Game.by_report_token(token).id == game


def test_an_unknown_token_resolves_to_nothing(app, game):
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        db.session.get(Game, game).mint_report_token()
        assert Game.by_report_token("f" * 32) is None


def test_an_empty_token_resolves_to_nothing(app, game):
    """A machine with no label yet has report_token NULL, and "" must not match it."""
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        db.session.add(Game(name="No Label Yet", barcode="no-label-yet"))
        db.session.commit()
        for empty in ("", None):
            assert Game.by_report_token(empty) is None


def test_rotating_replaces_the_token_and_retires_the_old_one(app, game):
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        row = db.session.get(Game, game)
        old = row.mint_report_token()
        new = row.rotate_report_token()
        assert new != old
        assert HEX32.match(new)
        assert Game.by_report_token(old) is None
        assert Game.by_report_token(new).id == game


def test_rotating_flags_the_label_for_reprint(app, game):
    """A rotated token with the old label still in the door is a dead QR, so the machine
    has to show up on a reprint list rather than being quietly broken."""
    from app.extensions import db
    from app.models import Game

    with app.app_context():
        row = db.session.get(Game, game)
        row.mint_report_token()
        assert row.report_label_stale is False
        row.rotate_report_token()
        assert row.report_label_stale is True
