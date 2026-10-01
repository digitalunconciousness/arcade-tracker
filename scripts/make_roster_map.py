#!/usr/bin/env python3
"""Propose a mapping from the machines in the database to roster slugs.

Output is a review file, not an answer. Entries the script is certain about are
marked ``"confirmed": true``; everything else is ``false`` and waits for a human.
The data migration applies only confirmed entries and reports the rest, which is
what "ambiguity is reported, never guessed" means in practice.

    python scripts/make_roster_map.py ROSTER.json -o roster-map.json
    python scripts/make_roster_map.py ROSTER.json --db sqlite:///snapshot.db

The roster and the map both contain the real floor list, so **neither belongs in
this repository** (GATBOX CLAUDE.md rule 13). Keep them outside it. This script is
generic and carries no data, so it is committed; its tests use synthetic rosters.

Tiers
  exact          name matches and the existing barcode already equals the slug
  slug_differs   name matches, barcode must change
  kind_resolved  several roster entries share the name; video/pinball settled it
  proposed       fuzzy match -- REVIEW: the reason says why it is believable
  unresolved     no candidate, or several equally good ones -- REVIEW
  import         roster machines with no row in the database
"""
from __future__ import annotations

import argparse
import datetime as dt
import difflib
import hashlib
import json
import os
import re
import sys
import unicodedata

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

KINDS = ("video_games", "pinball", "retired")
STRONG, WEAK = 0.85, 0.62      # similarity bands for a proposal
CLOSE = 0.04                   # two candidates within this of each other are a tie


def norm(text: str | None) -> str:
    """Compare names without punctuation, case or accents getting in the way."""
    ascii_text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "", ascii_text.lower())


def ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def why(tracker_name: str, roster_name: str, score: float) -> str:
    """A human-checkable reason, because a bare score is not reviewable."""
    t, r = norm(tracker_name), norm(roster_name)
    if score >= 0.93:
        return "spelling differs by a character or two"
    if len(r) <= len(t) * 0.6 and all(c in t for c in r):
        return "roster uses an abbreviation of the tracker's name"
    if r in t or t in r:
        return "one name contains the other"
    if score >= STRONG:
        return "names are close"
    return "names are only loosely similar -- check this one properly"


def is_pinball(genre: str | None, name: str) -> bool:
    blob = f"{genre or ''} {name}".lower()
    return "pinball" in blob or "pin-" in blob


def load_games(db_url: str) -> list[dict]:
    """Read id, name, barcode, genre. A snapshot taken before migration
    c1a2b3d4e5f6 has no barcode, so reproduce what that migration would have
    generated -- deterministic in id order -- to show what would change."""
    import sqlalchemy as sa
    from app.utils.helpers import generate_unique_barcode

    engine = sa.create_engine(db_url)
    with engine.connect() as conn:
        cols = {c for c in ("barcode", "genre")
                if conn.execute(sa.text(
                    "SELECT COUNT(*) FROM information_schema.columns "
                    "WHERE table_name='game' AND column_name=:c"), {"c": c}).scalar()} \
            if engine.dialect.name != "sqlite" else \
            {r[1] for r in conn.execute(sa.text("PRAGMA table_info(game)"))} & {"barcode", "genre"}
        select = ", ".join(["id", "name"] + sorted(cols))
        rows = conn.execute(sa.text(f"SELECT {select} FROM game ORDER BY id")).mappings().all()

    taken: set[str] = set()
    games = []
    for row in rows:
        barcode = row.get("barcode")
        if not barcode:
            barcode = generate_unique_barcode(row["name"] or f"game-{row['id']}", taken)
        else:
            taken.add(barcode)
        games.append({"id": row["id"], "name": row["name"],
                      "barcode": barcode, "genre": row.get("genre")})
    return games


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("roster", help="the roster JSON (never committed)")
    p.add_argument("-o", "--out", default="roster-map.json")
    p.add_argument("--db", default=os.environ.get("DATABASE_URL"),
                   help="SQLAlchemy URL; defaults to DATABASE_URL")
    args = p.parse_args()
    if not args.db:
        print("no --db and no DATABASE_URL", file=sys.stderr)
        return 2

    raw = open(args.roster, "rb").read()
    roster = json.loads(raw)
    entries = [(k, e) for k in KINDS for e in (roster.get(k) or [])]
    if not entries:
        print(f"{args.roster} has no {' / '.join(KINDS)} entries", file=sys.stderr)
        return 2

    games = load_games(args.db)
    by_name: dict[str, list[tuple[str, dict]]] = {}
    for kind, entry in entries:
        by_name.setdefault(norm(entry.get("name")), []).append((kind, entry))

    mapped, review, claimed = [], [], set()

    def record(game, kind, entry, tier, confirmed, reason, score=None):
        row = {"game_id": game["id"], "name": game["name"],
               "current_barcode": game["barcode"], "roster_slug": entry["slug"],
               "roster_name": entry["name"], "kind": kind, "tier": tier,
               "confirmed": confirmed, "reason": reason}
        if score is not None:
            row["similarity"] = round(score, 3)
        (mapped if confirmed else review).append(row)
        claimed.add(entry["slug"])

    for game in games:
        hits = by_name.get(norm(game["name"]), [])
        if len(hits) == 1:
            kind, entry = hits[0]
            same = entry["slug"] == game["barcode"]
            record(game, kind, entry, "exact" if same else "slug_differs", True,
                   "name matches the roster exactly"
                   + ("" if same else "; the generated barcode differs from the roster slug"))
            continue
        if len(hits) > 1:
            want_pin = is_pinball(game["genre"], game["name"])
            narrowed = [(k, e) for k, e in hits if (k == "pinball") == want_pin]
            if len(narrowed) == 1:
                kind, entry = narrowed[0]
                record(game, kind, entry, "kind_resolved", True,
                       f"several roster entries share this name; "
                       f"{'pinball' if want_pin else 'video'} settled it (genre={game['genre']!r})")
            else:
                review.append({"game_id": game["id"], "name": game["name"],
                               "current_barcode": game["barcode"], "roster_slug": None,
                               "kind": None, "tier": "unresolved", "confirmed": False,
                               "reason": "several roster entries share this name and the kind "
                                         "does not separate them -- choose one",
                               "candidates": [{"slug": e["slug"], "name": e["name"], "kind": k}
                                              for k, e in hits]})
            continue

        free = [(k, e) for k, e in entries if e["slug"] not in claimed]
        scored = sorted(((ratio(norm(game["name"]), norm(e["name"])), k, e) for k, e in free),
                        key=lambda t: t[0], reverse=True)
        if not scored or scored[0][0] < WEAK:
            review.append({"game_id": game["id"], "name": game["name"],
                           "current_barcode": game["barcode"], "roster_slug": None,
                           "kind": None, "tier": "unresolved", "confirmed": False,
                           "reason": "no roster entry resembles this name -- a machine the roster "
                                     "does not list, a second cabinet of one it does, or a junk row",
                           "candidates": [{"slug": e["slug"], "name": e["name"], "kind": k,
                                           "similarity": round(s, 3)} for s, k, e in scored[:3]]})
            continue
        best, rest = scored[0], scored[1:2]
        if rest and best[0] - rest[0][0] < CLOSE:
            review.append({"game_id": game["id"], "name": game["name"],
                           "current_barcode": game["barcode"], "roster_slug": None,
                           "kind": None, "tier": "unresolved", "confirmed": False,
                           "reason": "two roster entries fit equally well -- choose one",
                           "candidates": [{"slug": e["slug"], "name": e["name"], "kind": k,
                                           "similarity": round(s, 3)} for s, k, e in scored[:3]]})
            continue
        score, kind, entry = best
        record(game, kind, entry, "proposed", False,
               why(game["name"], entry["name"], score), score)

    to_import = [{"roster_slug": e["slug"], "roster_name": e["name"], "kind": k,
                  "confirmed": False,
                  "reason": "in the roster, no row in the database -- import as a new machine"}
                 for k, e in entries if e["slug"] not in claimed]

    doc = {
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "roster_file": os.path.basename(args.roster),
        "roster_sha256": hashlib.sha256(raw).hexdigest(),
        "roster_machines": len(entries),
        "database_machines": len(games),
        "how_to_review": [
            "Only entries with \"confirmed\": true are applied by the migration.",
            "For each entry in needs_review: check roster_slug, correct it if wrong,",
            "then set \"confirmed\": true. Leave it false to skip that machine entirely.",
            "For an unresolved entry, copy the slug you want from candidates into roster_slug.",
            "Delete an entry instead of confirming it if the machine should be left alone.",
        ],
        "counts": {
            "auto_confirmed": len(mapped),
            "needs_review": len(review),
            "to_import": len(to_import),
        },
        "confirmed": sorted(mapped, key=lambda r: (r["tier"], r["name"].lower())),
        "needs_review": sorted(review, key=lambda r: (r["tier"], r["name"].lower())),
        "to_import": sorted(to_import, key=lambda r: (r["kind"], r["roster_name"].lower())),
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    print(f"wrote {args.out}")
    for tier in ("exact", "slug_differs", "kind_resolved"):
        n = sum(1 for r in mapped if r["tier"] == tier)
        if n:
            print(f"  {tier:14} {n:3}  (confirmed automatically)")
    for tier in ("proposed", "unresolved"):
        n = sum(1 for r in review if r["tier"] == tier)
        if n:
            print(f"  {tier:14} {n:3}  NEEDS REVIEW")
    print(f"  {'to_import':14} {len(to_import):3}  NEEDS REVIEW")
    return 0


if __name__ == "__main__":
    sys.exit(main())
