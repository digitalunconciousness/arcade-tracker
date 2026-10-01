"""The roster importer, on invented machines.

The bug this guards: the importer used to generate a barcode from the machine's
name instead of using the roster's own ``slug``. The two differ -- ``devil-s-hollow``
against the roster's ``devils-hollow`` -- so the tracker and GATBOX could not refer
to the same machine, and every QR label encoded an identifier GATBOX had never
heard of.
"""
from __future__ import annotations

import pytest


def _roster(**over):
    base = {
        "meta": {"platforms": {"plat_a": {"desc": "Platform A"}}},
        "video_games": [
            {"slug": "widget-wars", "name": "Widget Wars", "mfr": "Acme",
             "platform": "plat_a", "faults": [], "parts": [], "risk": [], "notes": ""},
        ],
        "pinball": [
            {"slug": "pin-sprocket", "name": "Sprocket", "mfr": "Bally",
             "platform": "plat_a", "faults": [], "parts": [], "risk": [], "notes": ""},
        ],
        "retired": [],
    }
    base.update(over)
    return base


def _import(app, data):
    from app.extensions import db
    from app.utils.helpers import import_games_from_roster
    with app.app_context():
        result = import_games_from_roster(data)
        db.session.commit()
        return result


def _games(app):
    from app.models import Game
    with app.app_context():
        return {g.name: g.barcode for g in Game.query.all()}


def test_the_roster_slug_becomes_the_barcode(app):
    result = _import(app, _roster())
    assert result["added"] == 2 and not result["errors"]
    assert _games(app) == {"Widget Wars": "widget-wars", "Sprocket": "pin-sprocket"}


def test_the_slug_is_used_verbatim_even_when_a_name_would_slugify_differently(app):
    """The whole point: ``Devil's Hollow`` slugifies to devil-s-hollow, and the
    roster says devils-hollow. The roster wins."""
    data = _roster(video_games=[{"slug": "devils-hollow", "name": "Devil's Hollow",
                                 "mfr": "Bally", "platform": "plat_a"}])
    _import(app, data)
    assert _games(app)["Devil's Hollow"] == "devils-hollow"

    from app.utils.helpers import generate_unique_barcode
    assert generate_unique_barcode("Devil's Hollow", set()) == "devil-s-hollow", (
        "if this ever equals the roster slug the regression this guards has gone away"
    )


def test_pinball_keeps_its_pin_prefix(app):
    _import(app, _roster())
    assert _games(app)["Sprocket"] == "pin-sprocket"


def test_an_entry_with_no_slug_is_an_error_not_an_invented_slug(app):
    data = _roster(video_games=[{"name": "Nameless Slug", "mfr": "Acme"}])
    result = _import(app, data)
    assert result["added"] == 1, "only the pinball entry"
    assert any("no slug" in e for e in result["errors"])
    assert "Nameless Slug" not in _games(app)


def test_importing_twice_adds_nothing(app):
    first = _import(app, _roster())
    second = _import(app, _roster())
    assert first["added"] == 2
    assert second["added"] == 0 and second["skipped"] == 2
    assert len(_games(app)) == 2


def test_a_machine_already_present_under_another_barcode_is_reported_not_duplicated(app):
    """A machine entered under a joke name, or before the mapping ran."""
    from app.extensions import db
    from app.models import Game
    with app.app_context():
        db.session.add(Game(name="Widget Wars", barcode="widget-wars-2"))
        db.session.commit()
    result = _import(app, _roster())
    assert result["added"] == 1, "the pinball entry only"
    assert any("different barcode" in e and "widget-wars" in e for e in result["errors"])
    names = _games(app)
    assert names["Widget Wars"] == "widget-wars-2", "left alone for the migration to fix"


def test_two_machines_sharing_a_name_both_import_under_their_own_slugs(app):
    """A video Batman and a pinball Batman are different machines."""
    data = _roster(
        video_games=[{"slug": "batman", "name": "Batman", "mfr": "Atari"}],
        pinball=[{"slug": "pin-batman", "name": "Batman", "mfr": "Data East"}],
    )
    result = _import(app, data)
    assert result["added"] == 2, "different kinds, so both are real machines"
    assert result["errors"] == []
    assert _games(app)["Batman"] in ("batman", "pin-batman")


def test_a_pinball_imports_alongside_a_video_game_already_in_the_database(app):
    """The case that matters on the floor: the video game is already a row.

    Seeding the name guard from the whole table used to block the pinball, which
    would have left the roster's pinball side unimportable.
    """
    _import(app, _roster(video_games=[{"slug": "batman", "name": "Batman", "mfr": "Atari"}],
                         pinball=[]))
    result = _import(app, _roster(video_games=[],
                                  pinball=[{"slug": "pin-batman", "name": "Batman",
                                            "mfr": "Data East"}]))
    assert result["added"] == 1, result["errors"]
    assert result["errors"] == []
    from app.models import Game
    with app.app_context():
        assert Game.query.filter_by(barcode="pin-batman").one().genre == "Pinball"
        assert Game.query.filter_by(barcode="batman").one().genre != "Pinball"


def test_the_same_pinball_twice_is_still_reported_not_duplicated(app):
    """Kind-awareness must not turn the guard off for the case it exists for."""
    _import(app, _roster(video_games=[], pinball=[{"slug": "pin-batman", "name": "Batman"}]))
    result = _import(app, _roster(video_games=[],
                                  pinball=[{"slug": "pin-batman-new", "name": "Batman"}]))
    assert result["added"] == 0
    assert any("different barcode" in e for e in result["errors"])


def test_retired_machines_land_in_the_warehouse(app):
    data = _roster(video_games=[], pinball=[],
                   retired=[{"slug": "pin-old-thing", "name": "Old Thing", "mfr": "Gottlieb"}])
    _import(app, data)
    from app.models import Game
    with app.app_context():
        game = Game.query.filter_by(barcode="pin-old-thing").one()
        assert game.location == "Warehouse" and game.status == "Retired"
