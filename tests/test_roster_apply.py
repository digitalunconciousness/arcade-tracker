"""scripts/apply_roster_map.py, on synthetic data only.

Every machine here is invented. What these tests are really about is the refusals:
the script rewrites the identifier that printed labels and the bench both depend on,
so it has to stop rather than guess whenever the map and the database disagree.

The fixture database puts a UNIQUE index on ``barcode``, like the real schema, so the
two-pass update is tested against the constraint it exists for.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "scripts", "apply_roster_map.py")


def _db(path, rows):
    con = sqlite3.connect(path)
    con.execute(
        "CREATE TABLE game (id INTEGER PRIMARY KEY, name TEXT, "
        "barcode TEXT UNIQUE, genre TEXT)"
    )
    con.executemany("INSERT INTO game (id, name, barcode) VALUES (?,?,?)", rows)
    con.commit()
    con.close()


def _barcodes(path):
    con = sqlite3.connect(path)
    out = dict(con.execute("SELECT id, barcode FROM game").fetchall())
    con.close()
    return out


def _confirmed(game_id, name, current, slug):
    return {"game_id": game_id, "name": name, "current_barcode": current,
            "roster_slug": slug, "roster_name": name, "kind": "video_games",
            "tier": "slug_differs", "confirmed": True, "reason": "test fixture"}


def _map(confirmed, **sections):
    doc = {"generated": "2026-01-01T00:00:00+00:00", "roster_file": "synthetic.json",
           "confirmed": confirmed, "needs_review": [], "to_import": [],
           "not_imported_on_purpose": []}
    doc.update(sections)
    return doc


@pytest.fixture()
def site(tmp_path):
    """A three-machine database and a map that renames two of them."""
    db = tmp_path / "test.db"
    _db(db, [(1, "Widget Wars", "widget-wars"),
             (2, "Cogs n Gears", "cogs-n-gears-7a3f"),
             (3, "Sprocket", None)])
    doc = _map([
        _confirmed(1, "Widget Wars", "widget-wars", "widget-wars"),      # already correct
        _confirmed(2, "Cogs n Gears", "cogs-n-gears-7a3f", "cogs-n-gears"),
        _confirmed(3, "Sprocket", None, "sprocket"),
    ])
    path = tmp_path / "map.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return {"db": str(db), "map": path, "doc": doc, "tmp": tmp_path}


def run(site, *args, map_doc=None, input_text=None):
    """Run the script against the fixture, optionally with a rewritten map."""
    if map_doc is not None:
        site["map"].write_text(json.dumps(map_doc), encoding="utf-8")
    cmd = [sys.executable, SCRIPT, "--map", str(site["map"]),
           "--db", f"sqlite:///{site['db']}", *args]
    return subprocess.run(cmd, capture_output=True, text=True,
                          input=input_text, cwd=REPO_ROOT, timeout=120)


# --- the happy path -------------------------------------------------------

def test_dry_run_reports_but_writes_nothing(site):
    before = _barcodes(site["db"])
    r = run(site)
    assert r.returncode == 0, r.stderr
    assert "DRY RUN" in r.stdout
    assert "2 change(s) ready" in r.stdout
    assert "1 already correct" in r.stdout
    assert "cogs-n-gears-7a3f -> cogs-n-gears" in r.stdout
    assert _barcodes(site["db"]) == before


def test_apply_writes_the_confirmed_entries(site):
    r = run(site, "--apply", "--yes")
    assert r.returncode == 0, r.stderr
    assert _barcodes(site["db"]) == {1: "widget-wars", 2: "cogs-n-gears", 3: "sprocket"}
    assert "verified" in r.stdout


def test_a_second_run_finds_nothing_to_do(site):
    assert run(site, "--apply", "--yes").returncode == 0
    r = run(site, "--apply", "--yes")
    assert r.returncode == 0, r.stderr
    assert "Nothing to do" in r.stdout


def test_two_machines_can_trade_identifiers(site):
    """The unique index would reject this one statement at a time."""
    db = site["tmp"] / "swap.db"
    _db(db, [(1, "Alpha", "beta"), (2, "Beta", "alpha")])
    site["db"] = str(db)
    r = run(site, "--apply", "--yes", map_doc=_map([
        _confirmed(1, "Alpha", "beta", "alpha"),
        _confirmed(2, "Beta", "alpha", "beta"),
    ]))
    assert r.returncode == 0, r.stderr
    assert _barcodes(db) == {1: "alpha", 2: "beta"}


# --- what it refuses to do ------------------------------------------------

@pytest.mark.parametrize("confirmed_value", [False, "true", None])
def test_an_unconfirmed_entry_in_the_confirmed_list_is_refused(site, confirmed_value):
    row = _confirmed(2, "Cogs n Gears", "cogs-n-gears-7a3f", "cogs-n-gears")
    row["confirmed"] = confirmed_value
    before = _barcodes(site["db"])
    r = run(site, "--apply", "--yes", map_doc=_map([row]))
    assert r.returncode == 1
    assert "REFUSED" in r.stderr and "not true" in r.stderr
    assert _barcodes(site["db"]) == before


def test_a_renamed_machine_is_refused(site):
    con = sqlite3.connect(site["db"])
    con.execute("UPDATE game SET name = 'Cogs and Gears' WHERE id = 2")
    con.commit()
    con.close()
    before = _barcodes(site["db"])
    r = run(site, "--apply", "--yes")
    assert r.returncode == 1
    assert "renamed since the map was made" in r.stderr
    assert _barcodes(site["db"]) == before


def test_a_barcode_edited_since_the_map_was_made_is_refused(site):
    con = sqlite3.connect(site["db"])
    con.execute("UPDATE game SET barcode = 'edited-by-hand' WHERE id = 2")
    con.commit()
    con.close()
    r = run(site, "--apply", "--yes")
    assert r.returncode == 1
    assert "changed since, regenerate the map" in r.stderr
    assert _barcodes(site["db"])[2] == "edited-by-hand"


def test_a_missing_machine_is_refused(site):
    r = run(site, "--apply", "--yes", map_doc=_map([
        _confirmed(99, "Ghost Machine", None, "ghost-machine")]))
    assert r.returncode == 1
    assert "no longer in the database" in r.stderr


def test_two_machines_claiming_one_slug_is_refused(site):
    r = run(site, "--apply", "--yes", map_doc=_map([
        _confirmed(2, "Cogs n Gears", "cogs-n-gears-7a3f", "sprocket"),
        _confirmed(3, "Sprocket", None, "sprocket"),
    ]))
    assert r.returncode == 1
    assert "claimed twice" in r.stderr


def test_the_same_machine_listed_twice_is_refused(site):
    r = run(site, "--apply", "--yes", map_doc=_map([
        _confirmed(3, "Sprocket", None, "sprocket"),
        _confirmed(3, "Sprocket", None, "sprocket-two"),
    ]))
    assert r.returncode == 1
    assert "appears twice" in r.stderr


@pytest.mark.parametrize("slug", ["", "-leading-dash", "has space", "a/b", "x" * 65, None, 7])
def test_an_unusable_slug_is_refused(site, slug):
    r = run(site, "--apply", "--yes", map_doc=_map([
        _confirmed(3, "Sprocket", None, slug)]))
    assert r.returncode == 1
    assert "not a usable slug" in r.stderr


def test_a_slug_held_by_an_untouched_machine_is_refused(site):
    """Machine 3 wants a slug machine 1 is sitting on, and 1 is not in the map."""
    r = run(site, "--apply", "--yes", map_doc=_map([
        _confirmed(3, "Sprocket", None, "widget-wars")]))
    assert r.returncode == 1
    assert "belongs to 'Widget Wars'" in r.stderr


def test_a_placeholder_left_by_an_interrupted_run_is_refused(site):
    con = sqlite3.connect(site["db"])
    con.execute("UPDATE game SET barcode = '__applying-3' WHERE id = 3")
    con.commit()
    con.close()
    r = run(site, "--apply", "--yes")
    assert r.returncode == 1
    assert "interrupted run" in r.stderr


def test_apply_without_yes_refuses_when_not_a_terminal(site):
    before = _barcodes(site["db"])
    r = run(site, "--apply", input_text="apply\n")
    assert r.returncode == 1
    assert "without --yes" in r.stderr
    assert _barcodes(site["db"]) == before


def test_a_map_that_is_not_a_map_is_rejected(site):
    site["map"].write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    r = run(site)
    assert r.returncode == 2
    assert "not a roster map" in r.stderr


# --- the skip report and the reprint list ---------------------------------

def test_every_unapplied_entry_is_named(site):
    doc = _map(
        [_confirmed(2, "Cogs n Gears", "cogs-n-gears-7a3f", "cogs-n-gears")],
        needs_review=[{"game_id": 3, "name": "Sprocket", "roster_slug": None,
                       "tier": "unresolved", "confirmed": False,
                       "reason": "two cabinets share this name"}],
        to_import=[{"roster_slug": "lonely", "roster_name": "Lonely Machine",
                    "kind": "video_games", "confirmed": False, "reason": "no row yet"}],
        not_imported_on_purpose=[{"roster_slug": "twin-b", "roster_name": "Twin B",
                                  "kind": "video_games", "reason": "shares a cabinet"}],
    )
    r = run(site, map_doc=doc)
    assert r.returncode == 0, r.stderr
    for expected in ("needs_review (1)", "two cabinets share this name",
                     "to_import (1)", "Lonely Machine",
                     "not_imported_on_purpose (1)", "shares a cabinet",
                     "3 entry(ies) left alone"):
        assert expected in r.stdout, expected


def test_the_reprint_list_names_each_label_and_its_page(site):
    out = site["tmp"] / "reprint.json"
    r = run(site, "--apply", "--yes", "--reprint-out", str(out),
            "--base-url", "http://hub.example.test")
    assert r.returncode == 0, r.stderr
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["count"] == 2
    assert {m["name"] for m in doc["machines"]} == {"Cogs n Gears", "Sprocket"}
    cogs = next(m for m in doc["machines"] if m["game_id"] == 2)
    assert cogs["old_barcode"] == "cogs-n-gears-7a3f"
    assert cogs["new_barcode"] == "cogs-n-gears"
    assert cogs["label_page"] == "http://hub.example.test/game/2/label"
    assert oct(out.stat().st_mode)[-3:] == "600"


def test_the_reprint_list_may_not_be_written_into_the_repository(site):
    inside = os.path.join(REPO_ROOT, "reprint-should-not-exist.json")
    r = run(site, "--apply", "--yes", "--reprint-out", inside)
    assert r.returncode == 1
    assert "inside the repository" in r.stderr
    assert not os.path.exists(inside)
    # the barcodes still went in: the refusal is about where the list was written
    assert _barcodes(site["db"])[2] == "cogs-n-gears"
