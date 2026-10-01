#!/usr/bin/env python3
"""Compare the live database's schema against the models, and say where Alembic
should be stamped.

Written after `flask db stamp head` was run against a database whose schema was
*older* than head. Stamping marks migrations as applied without running them, so
`game.barcode` was never created and every page touching a Game raised
`UndefinedColumn`. Checking that all the expected tables existed was not enough:
the tables were all there, and a column was not.

    python scripts/check_schema.py            # report
    python scripts/check_schema.py --quiet    # exit 1 if anything is missing

Never `stamp head` on a database you have not checked. Stamp the revision whose
changes are actually present, then `db upgrade` and let Alembic do the work.
"""
from __future__ import annotations

import argparse
import os
import sys

import sqlalchemy as sa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Which migration introduced each column, so a gap points at a revision.
# Keep in step with migrations/versions/.
INTRODUCED_BY = {
    ("maintenance_record", "priority"): "ebead5244def",
    ("inventory_request", "maintenance_id"): "3e5463d29981",
    ("inventory_request", "tracking_number"): "e7582856b8aa",
    ("inventory_request", "vendor"): "e7582856b8aa",
    ("inventory_request", "estimated_arrival"): "e7582856b8aa",
    ("inventory_request", "carrier"): "8dcea35845db",
    ("inventory_request", "tracking_status"): "8dcea35845db",
    ("inventory_request", "tracking_details"): "8dcea35845db",
    ("inventory_request", "last_tracking_update"): "8dcea35845db",
    ("maintenance_record", "work_order_type"): "b547f37c117c",
    ("maintenance_record", "location_description"): "b547f37c117c",
    ("game", "last_ranking_update"): "7a61de1d1679",
    ("game", "barcode"): "c1a2b3d4e5f6",
}

# The revision that precedes each, i.e. what to stamp so `upgrade` will apply it.
PREDECESSOR = {
    "ebead5244def": "5a026e6869ec",
    "3e5463d29981": "ebead5244def",
    "e7582856b8aa": "3e5463d29981",
    "8dcea35845db": "e7582856b8aa",
    "b547f37c117c": "8dcea35845db",
    "7a61de1d1679": "b547f37c117c",
    "c1a2b3d4e5f6": "7a61de1d1679",
    "f1c2d3e4a5b6": "c1a2b3d4e5f6",
}

ORDER = ["5a026e6869ec", "ebead5244def", "3e5463d29981", "e7582856b8aa",
         "8dcea35845db", "b547f37c117c", "7a61de1d1679", "c1a2b3d4e5f6",
         "f1c2d3e4a5b6"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--quiet", action="store_true", help="only report problems")
    args = p.parse_args()

    from app import create_app
    from app.extensions import db

    app = create_app()
    with app.app_context():
        uri = app.config["SQLALCHEMY_DATABASE_URI"]
        print("database:", uri.split("@")[-1] if "@" in uri else uri)
        inspector = sa.inspect(db.engine)
        live_tables = set(inspector.get_table_names())

        missing_tables = sorted(set(db.metadata.tables) - live_tables)
        missing_columns: list[tuple[str, str]] = []
        for name, table in db.metadata.tables.items():
            if name not in live_tables:
                continue
            live = {c["name"] for c in inspector.get_columns(name)}
            for column in table.columns:
                if column.name not in live:
                    missing_columns.append((name, column.name))

        stamped = None
        if "alembic_version" in live_tables:
            stamped = db.session.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar()
        print("alembic  :", stamped or "NOT STAMPED (no alembic_version row)")

        if not missing_tables and not missing_columns:
            if not args.quiet:
                print("schema   : matches the models")
                if stamped != ORDER[-1]:
                    print(f"\nNote: the schema is complete but stamped at {stamped!r},"
                          f" not head ({ORDER[-1]}).")
                    print("`db upgrade` may try to re-apply changes that already exist.")
            return 0

        print("\nSCHEMA IS BEHIND THE MODELS")
        for name in missing_tables:
            print(f"  missing table : {name}")
        for table, column in missing_columns:
            rev = INTRODUCED_BY.get((table, column), "?")
            print(f"  missing column: {table}.{column}   (added by {rev})")

        revs = {INTRODUCED_BY[k] for k in missing_columns if k in INTRODUCED_BY}
        if revs:
            earliest = min(revs, key=ORDER.index)
            target = PREDECESSOR.get(earliest)
            print(f"\nEarliest missing change comes from {earliest}.")
            print("To repair, stamp the revision before it and let Alembic run the rest:")
            print(f"  flask --app run:app db stamp {target}")
            print("  flask --app run:app db upgrade")
        else:
            print("\nMissing tables only; `flask --app run:app db upgrade` may be enough.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
