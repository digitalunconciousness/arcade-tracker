#!/usr/bin/env python3
"""Apply a reviewed roster map: each machine's ``barcode`` becomes its roster slug.

    python scripts/apply_roster_map.py --map roster-map.json              # dry run
    python scripts/apply_roster_map.py --map roster-map.json --apply
    python scripts/apply_roster_map.py --map roster-map.json --apply --yes  # no prompt

This is the other half of ``make_roster_map.py``. That script proposes; a person
reviews; this one applies **only** the entries marked ``"confirmed": true`` and
prints every entry it is leaving alone, so "ambiguity is reported, never guessed"
survives all the way to the database.

Why a script and not an Alembic revision
    The map is the real floor list, so it can never be committed, and an Alembic
    revision cannot be handed a file path. House rule is that data migrations stay
    separate from schema migrations anyway: ``flask db upgrade`` changes shape, this
    changes rows, and the two are reviewed and run independently.

Why ``barcode`` is the shared identifier
    It is already what printed labels encode (``<base>/g/<barcode>``) and what the
    scan kiosk resolves. Making it equal the roster slug is what lets a code scanned
    on the bench and a code scanned at the cabinet mean the same machine, with no
    translation table in between.

Safety
    * dry run unless ``--apply``; the dry run prints exactly what would change
    * refuses outright if the database has moved on since the map was made -- a
      renamed machine, a barcode edited by hand, a missing row
    * one transaction, and barcodes are moved in two passes so a pair of machines
      swapping identifiers cannot trip the unique index half-way through
    * idempotent: a second run finds nothing to do
    * rewriting a barcode orphans the printed label, so every change lands in a
      reprint list (``--reprint-out``)

Take a dump first. ``deploy/deploy.sh`` does that for you, which is the reason to
run this through a deploy rather than by hand.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

import sqlalchemy as sa

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The column is String(64); GATBOX's scanner accepts the same shape, and a slug that
# round-trips through a URL path and a QR code has no room for anything else.
SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TMP_PREFIX = "__applying-"          # pass-one placeholder; never a real barcode


class Refused(Exception):
    """The map and the database disagree. Nothing is written."""


def load_map(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("confirmed"), list):
        raise Refused(f"{path} is not a roster map (no 'confirmed' list)")
    return doc


def live_games(conn) -> dict[int, dict]:
    rows = conn.execute(sa.text("SELECT id, name, barcode FROM game")).mappings().all()
    return {r["id"]: dict(r) for r in rows}


def plan(doc: dict, games: dict[int, dict]) -> tuple[list[dict], list[dict], list[str]]:
    """Work out what to change, without touching anything.

    Returns (changes, already_correct, problems). A non-empty *problems* means the
    whole run is refused: a map that is stale in one place is not trustworthy in
    the others, and half an identity change is worse than none.
    """
    changes: list[dict] = []
    already: list[dict] = []
    problems: list[str] = []

    seen_ids: dict[int, str] = {}
    seen_slugs: dict[str, str] = {}

    for row in doc["confirmed"]:
        name = row.get("name")
        slug = row.get("roster_slug")
        game_id = row.get("game_id")

        if row.get("confirmed") is not True:
            problems.append(
                f"{name!r}: in the confirmed list but 'confirmed' is {row.get('confirmed')!r}, "
                f"not true -- move it to needs_review or set it to true"
            )
            continue
        if not isinstance(game_id, int):
            problems.append(f"{name!r}: game_id is {game_id!r}, not a number")
            continue
        if not isinstance(slug, str) or not SLUG.match(slug):
            problems.append(f"{name!r}: {slug!r} is not a usable slug (letters, digits, '.', '_', '-'; max 64)")
            continue
        if game_id in seen_ids:
            problems.append(f"game_id {game_id} appears twice: {seen_ids[game_id]!r} and {name!r}")
            continue
        if slug in seen_slugs:
            problems.append(f"slug {slug!r} claimed twice: {seen_slugs[slug]!r} and {name!r}")
            continue
        seen_ids[game_id], seen_slugs[slug] = name, name

        game = games.get(game_id)
        if game is None:
            problems.append(f"{name!r}: game {game_id} is no longer in the database -- regenerate the map")
            continue
        if (game["name"] or "") != (name or ""):
            problems.append(
                f"game {game_id} is now named {game['name']!r}, the map says {name!r} "
                f"-- renamed since the map was made, regenerate it"
            )
            continue

        current = game["barcode"] or ""
        if current == slug:
            already.append({"game_id": game_id, "name": name, "barcode": slug})
            continue
        if current and current != (row.get("current_barcode") or ""):
            problems.append(
                f"{name!r}: barcode is now {current!r}, the map was made when it was "
                f"{row.get('current_barcode')!r} -- changed since, regenerate the map"
            )
            continue
        changes.append({"game_id": game_id, "name": name, "old": current, "new": slug})

    # A slug this run wants, held by a machine the run is not touching.
    taken = {g["barcode"]: g for g in games.values() if g["barcode"]}
    moving = {c["game_id"] for c in changes}
    for c in changes:
        holder = taken.get(c["new"])
        if holder is not None and holder["id"] not in moving:
            problems.append(
                f"{c['name']!r} wants slug {c['new']!r}, which belongs to {holder['name']!r} "
                f"(game {holder['id']}) and this run does not move it"
            )

    leftover = sorted(b for b in taken if b.startswith(TMP_PREFIX))
    if leftover:
        problems.append(
            f"{len(leftover)} barcode(s) still hold a placeholder from an interrupted run "
            f"({leftover[0]} ...) -- restore the dump taken before that run"
        )
    return changes, already, problems


def apply_changes(conn, changes: list[dict]) -> None:
    """Move every barcode, in two passes, inside the caller's transaction.

    Pass one parks each changing row on a placeholder nobody else can hold, so the
    unique index cannot be tripped by two machines trading identifiers. Pass two
    writes the real slugs.
    """
    upd = sa.text("UPDATE game SET barcode = :barcode WHERE id = :id")
    for c in changes:
        conn.execute(upd, {"barcode": f"{TMP_PREFIX}{c['game_id']}", "id": c["game_id"]})
    for c in changes:
        conn.execute(upd, {"barcode": c["new"], "id": c["game_id"]})


def report_skips(doc: dict) -> int:
    """Name every entry that is deliberately not applied. Returns how many."""
    sections = (
        ("needs_review", "waiting on a person -- set \"confirmed\": true to apply"),
        ("to_import", "in the roster, no row in the database -- the importer adds these"),
        ("not_imported_on_purpose", "intentionally has no machine row"),
    )
    total = 0
    for key, why in sections:
        rows = doc.get(key) or []
        if not rows:
            continue
        total += len(rows)
        print(f"\n  {key} ({len(rows)}) -- {why}")
        for r in rows:
            label = r.get("name") or r.get("roster_name") or "?"
            slug = r.get("roster_slug")
            tier = r.get("tier") or r.get("kind") or ""
            print(f"    [{tier}] {label}" + (f" -> {slug}" if slug else "")
                  + (f"  ({r['reason']})" if r.get("reason") else ""))
    return total


def write_reprint_list(path: str, changes: list[dict], base_url: str) -> None:
    """The labels that stopped being true the moment the barcode moved."""
    real = os.path.realpath(path)
    if real.startswith(os.path.realpath(REPO_ROOT) + os.sep):
        raise Refused(
            f"refusing to write the reprint list inside the repository ({path}): "
            f"it names real machines. Put it somewhere outside the checkout."
        )
    doc = {
        "why": "the barcode changed, so the printed QR label no longer resolves",
        "count": len(changes),
        "machines": [
            {"game_id": c["game_id"], "name": c["name"], "old_barcode": c["old"],
             "new_barcode": c["new"], "label_page": f"{base_url}/game/{c['game_id']}/label"}
            for c in sorted(changes, key=lambda c: (c["name"] or "").lower())
        ],
    }
    with open(real, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
    os.chmod(real, 0o600)
    print(f"\nreprint list: {real} ({len(changes)} label(s), mode 600)")
    if not base_url:
        print("  (no --base-url and no BASE_URL, so label_page is a path, not a link)")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--map", required=True, help="the reviewed map from make_roster_map.py (never committed)")
    p.add_argument("--db", default=os.environ.get("DATABASE_URL"),
                   help="SQLAlchemy URL; defaults to DATABASE_URL")
    p.add_argument("--apply", action="store_true", help="write the changes (default is a dry run)")
    p.add_argument("--yes", action="store_true", help="skip the confirmation prompt")
    p.add_argument("--reprint-out", help="write the list of labels to reprint here (outside the repo)")
    p.add_argument("--base-url", default=os.environ.get("BASE_URL", ""),
                   help="prefix for the label links in the reprint list")
    args = p.parse_args()

    if not args.db:
        print("no --db and no DATABASE_URL", file=sys.stderr)
        return 2

    try:
        doc = load_map(args.map)
    except (OSError, ValueError, Refused) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    if os.path.realpath(args.map).startswith(os.path.realpath(REPO_ROOT) + os.sep):
        print(f"warning: the map is inside the repository ({args.map}). It is the real floor "
              f"list -- move it out before committing anything.", file=sys.stderr)

    engine = sa.create_engine(args.db)
    with engine.connect() as conn:
        games = live_games(conn)
        try:
            changes, already, problems = plan(doc, games)
        except Refused as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 1

    print(f"map:      {args.map}")
    print(f"          made {doc.get('generated', '?')} from {doc.get('roster_file', '?')}")
    print(f"database: {sa.make_url(args.db).render_as_string(hide_password=True)}")
    print(f"          {len(games)} machines\n")
    print(f"confirmed in the map:  {len(doc['confirmed'])}")
    print(f"  already correct:     {len(already)}")
    print(f"  barcode to change:   {len(changes)}")

    if problems:
        print(f"\nREFUSED -- {len(problems)} problem(s), nothing written:", file=sys.stderr)
        for msg in problems:
            print(f"  - {msg}", file=sys.stderr)
        print("\nNothing was changed. Regenerate the map against the current database "
              "and review it again.", file=sys.stderr)
        return 1

    if changes:
        print("\n  machines whose identifier changes (their labels must be reprinted):")
        for c in sorted(changes, key=lambda c: (c["name"] or "").lower()):
            print(f"    {c['name']}: {c['old'] or '(none)'} -> {c['new']}")

    skipped = report_skips(doc)

    if not args.apply:
        print(f"\nDRY RUN -- nothing written. {len(changes)} change(s) ready, "
              f"{len(already)} already correct, {skipped} entry(ies) left alone.")
        print("Re-run with --apply to write them, after a dump.")
        return 0

    if not changes:
        print("\nNothing to do: every confirmed machine already carries its roster slug.")
        return 0

    if not args.yes:
        if not sys.stdin.isatty():
            print("\nrefusing to apply without --yes when stdin is not a terminal", file=sys.stderr)
            return 1
        print(f"\nThis rewrites the identifier on {len(changes)} machine(s) and invalidates "
              f"{len(changes)} printed label(s).")
        if input("Type 'apply' to continue: ").strip() != "apply":
            print("cancelled, nothing written")
            return 1

    with engine.begin() as conn:
        apply_changes(conn, changes)
    print(f"\napplied: {len(changes)} barcode(s) now match the roster.")

    with engine.connect() as conn:
        after = live_games(conn)
    wrong = [c for c in changes if (after.get(c["game_id"], {}).get("barcode")) != c["new"]]
    if wrong:
        print(f"verify FAILED on {len(wrong)} row(s) -- restore the dump", file=sys.stderr)
        return 1
    print("verified: every change is in the database.")

    if args.reprint_out:
        try:
            write_reprint_list(args.reprint_out, changes, (args.base_url or "").rstrip("/"))
        except (OSError, Refused) as exc:
            print(f"\nthe barcodes are applied, but the reprint list was not written: {exc}",
                  file=sys.stderr)
            return 1
    else:
        print("\nNo --reprint-out given; the list above is the only record of which "
              "labels to reprint.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
