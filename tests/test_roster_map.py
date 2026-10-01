"""scripts/make_roster_map.py, on synthetic data only.

The real roster and the real map are the floor list and never enter this
repository, so every fixture here is invented. What matters is the tiering: a
machine is confirmed automatically only when the match is beyond doubt, and
everything else lands in needs_review with a reason a person can check.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "make_roster_map.py")


def _roster():
    return {
        "meta": {"platforms": {}},
        "video_games": [
            {"slug": "widget-wars", "name": "Widget Wars"},        # exact
            {"slug": "cogs-n-gears", "name": "Cogs 'n' Gears"},    # slug differs
            {"slug": "sprocket", "name": "Sprocket"},              # shares a name with pinball
            {"slug": "gizmo-deluxe", "name": "Gizmo Deluxe"},      # typo in the tracker
            {"slug": "zzz", "name": "ZZZ"},                        # abbreviation
            {"slug": "lonely", "name": "Lonely Machine"},          # to import
        ],
        "pinball": [
            {"slug": "pin-sprocket", "name": "Sprocket"},          # the other Sprocket
        ],
        "retired": [],
    }


def _db(path, rows):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE game (id INTEGER PRIMARY KEY, name TEXT, barcode TEXT, genre TEXT)")
    con.executemany("INSERT INTO game (id, name, barcode, genre) VALUES (?,?,?,?)", rows)
    con.commit()
    con.close()


@pytest.fixture()
def built(tmp_path):
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps(_roster()), encoding="utf-8")
    db = tmp_path / "games.db"
    _db(db, [
        (1, "Widget Wars", "widget-wars", "Action"),                   # exact
        (2, "Cogs 'n' Gears", "cogs-n-gears-2", "Action"),             # slug_differs
        (3, "Sprocket", "sprocket", "Pinball"),                        # kind_resolved -> pinball
        (4, "Gizmo Delux", "gizmo-delux", "Action"),                   # proposed (typo)
        (5, "Zig Zag Zoom", "zig-zag-zoom", "Action"),                 # unresolved
    ])
    out = tmp_path / "map.json"
    proc = subprocess.run(
        [sys.executable, SCRIPT, str(roster), "--db", f"sqlite:///{db}", "-o", str(out)],
        capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, proc.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def _by_name(doc, key):
    return {r["name"]: r for r in doc[key]}


def test_an_exact_name_and_slug_match_is_confirmed(built):
    row = _by_name(built, "confirmed")["Widget Wars"]
    assert row["tier"] == "exact" and row["confirmed"] is True
    assert row["roster_slug"] == "widget-wars"


def test_a_differing_slug_is_confirmed_but_flagged_as_a_change(built):
    row = _by_name(built, "confirmed")["Cogs 'n' Gears"]
    assert row["tier"] == "slug_differs" and row["confirmed"] is True
    assert (row["current_barcode"], row["roster_slug"]) == ("cogs-n-gears-2", "cogs-n-gears")


def test_a_shared_name_is_settled_by_video_or_pinball(built):
    row = _by_name(built, "confirmed")["Sprocket"]
    assert row["tier"] == "kind_resolved" and row["confirmed"] is True
    assert row["roster_slug"] == "pin-sprocket", "genre says pinball"


def test_a_fuzzy_match_is_proposed_with_a_reason_and_NOT_confirmed(built):
    row = _by_name(built, "needs_review")["Gizmo Delux"]
    assert row["tier"] == "proposed"
    assert row["confirmed"] is False, "a guess must never be applied unreviewed"
    assert row["roster_slug"] == "gizmo-deluxe"
    assert row["reason"] and row["similarity"] > 0.8


def test_no_plausible_match_is_unresolved_with_candidates(built):
    row = _by_name(built, "needs_review")["Zig Zag Zoom"]
    assert row["tier"] == "unresolved"
    assert row["confirmed"] is False and row["roster_slug"] is None
    assert row["candidates"], "an unresolved row must offer something to choose from"


def test_roster_machines_with_no_row_are_listed_to_import(built):
    slugs = {r["roster_slug"] for r in built["to_import"]}
    assert "lonely" in slugs
    assert all(r["confirmed"] is False for r in built["to_import"])


def test_nothing_is_confirmed_that_a_human_has_not_seen(built):
    """The whole safety property, asserted directly."""
    assert all(r["confirmed"] for r in built["confirmed"])
    assert not any(r["confirmed"] for r in built["needs_review"])
    assert all(r["tier"] in {"exact", "slug_differs", "kind_resolved"} for r in built["confirmed"])


def test_the_map_records_which_roster_it_came_from(built):
    assert len(built["roster_sha256"]) == 64
    assert built["roster_machines"] == 7 and built["database_machines"] == 5


# --- hints -------------------------------------------------------------------
# A hint is somebody's proposal, so it must never arrive pre-confirmed. These
# assert that, plus the two things hints are for: a roster that abbreviates where
# the database spells out, and entries that deliberately get no machine of their own.

@pytest.fixture()
def hinted(tmp_path):
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps(_roster()), encoding="utf-8")
    db = tmp_path / "games.db"
    _db(db, [
        (1, "Widget Wars", "widget-wars", "Action"),
        (2, "Zig Zag Zoom", "zig-zag-zoom", "Action"),   # only a hint can find this
        (3, "junk row", "junk-row", ""),                  # hinted to null
    ])
    hints = tmp_path / "hints.json"
    hints.write_text(json.dumps({
        "_note": ["documentation keys are ignored"],
        "Zig Zag Zoom": {"slug": "zzz", "reason": "roster abbreviates to ZZZ"},
        "junk row": {"slug": None, "reason": "left over from setup, delete it"},
        "_no_import": {"lonely": "shares a cabinet with another game"},
    }), encoding="utf-8")
    out = tmp_path / "map.json"
    proc = subprocess.run(
        [sys.executable, SCRIPT, str(roster), "--db", f"sqlite:///{db}",
         "--hints", str(hints), "-o", str(out)],
        capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 0, proc.stderr
    return json.loads(out.read_text(encoding="utf-8"))


def test_a_hint_fills_the_slug_but_still_needs_review(hinted):
    row = _by_name(hinted, "needs_review")["Zig Zag Zoom"]
    assert row["tier"] == "hinted"
    assert row["roster_slug"] == "zzz", "the slug is filled in so the review is a check"
    assert row["confirmed"] is False, "a hint is a proposal, not a verification"
    assert "abbreviat" in row["reason"]


def test_a_null_hint_marks_a_row_excluded_with_its_reason(hinted):
    row = _by_name(hinted, "needs_review")["junk row"]
    assert row["tier"] == "excluded" and row["roster_slug"] is None
    assert row["confirmed"] is False
    assert "delete" in row["reason"]


def test_no_import_keeps_a_roster_entry_out_of_the_import_list(hinted):
    assert "lonely" not in {r["roster_slug"] for r in hinted["to_import"]}
    kept = {r["roster_slug"]: r for r in hinted["not_imported_on_purpose"]}
    assert "lonely" in kept and "cabinet" in kept["lonely"]["reason"]


def test_hints_naming_an_unknown_slug_are_refused(tmp_path):
    roster = tmp_path / "roster.json"
    roster.write_text(json.dumps(_roster()), encoding="utf-8")
    db = tmp_path / "games.db"
    _db(db, [(1, "Widget Wars", "widget-wars", "Action")])
    hints = tmp_path / "hints.json"
    hints.write_text(json.dumps({"Widget Wars": "no-such-slug"}), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, SCRIPT, str(roster), "--db", f"sqlite:///{db}",
         "--hints", str(hints), "-o", str(tmp_path / "map.json")],
        capture_output=True, text=True, cwd=REPO_ROOT)
    assert proc.returncode == 2, "a typo in a hint must stop the run, not be applied"
    assert "not in the roster" in proc.stderr


def test_hints_never_widen_what_is_auto_confirmed(hinted):
    assert all(r["tier"] in {"exact", "slug_differs", "kind_resolved"}
               for r in hinted["confirmed"])
