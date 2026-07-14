#!/usr/bin/env python3
"""Mirror the local SQLite arcade DB into a homelab Postgres instance.

The app keeps running against local SQLite (see app/__init__.py) so it never
depends on catbox's internet connection. This script is a one-way, run-it-
whenever sync: it upserts every row from SQLite into POSTGRES_SYNC_URL, for
reporting/backup purposes on the homelab side.

Safe to run on a timer with no network: failures are caught and logged, and
the next scheduled run just retries (every row is upserted by primary key, so
re-running after a partial or failed sync never duplicates anything).

Usage:
    POSTGRES_SYNC_URL=postgresql://user:pass@homelab-host:5432/arcade \
        python scripts/sync_to_postgres.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.extensions import db

CHUNK_SIZE = 500


def _fix_sequence(dest, table_name: str, pk_col: str) -> None:
    """Advance table_name's serial sequence past the mirrored id values.

    No-ops if the column isn't backed by a sequence (e.g. composite-key
    association tables), via the IS NOT NULL guard. table_name/pk_col come
    from our own SQLAlchemy metadata, never user input.
    """
    dest.execute(
        text(
            f"""
            DO $$
            DECLARE seq text;
            BEGIN
                seq := pg_get_serial_sequence('{table_name}', '{pk_col}');
                IF seq IS NOT NULL THEN
                    PERFORM setval(
                        seq,
                        COALESCE((SELECT MAX("{pk_col}") FROM "{table_name}"), 1)
                    );
                END IF;
            END $$;
            """
        )
    )


def sync() -> None:
    postgres_url = os.environ.get("POSTGRES_SYNC_URL")
    if not postgres_url:
        print("POSTGRES_SYNC_URL not set; nothing to sync.")
        return

    app = create_app()
    with app.app_context():
        sqlite_engine = db.engine
        metadata = db.metadata

        pg_engine = create_engine(postgres_url)
        metadata.create_all(bind=pg_engine)  # idempotent; mirrors the current models

        with sqlite_engine.connect() as source, pg_engine.begin() as dest:
            for table in metadata.sorted_tables:
                rows = [dict(row._mapping) for row in source.execute(select(table))]
                if not rows:
                    continue

                pk_cols = [c.name for c in table.primary_key.columns]
                update_cols = [c.name for c in table.columns if c.name not in pk_cols]

                for i in range(0, len(rows), CHUNK_SIZE):
                    chunk = rows[i : i + CHUNK_SIZE]
                    stmt = pg_insert(table).values(chunk)
                    if update_cols:
                        stmt = stmt.on_conflict_do_update(
                            index_elements=pk_cols,
                            set_={name: stmt.excluded[name] for name in update_cols},
                        )
                    else:
                        stmt = stmt.on_conflict_do_nothing(index_elements=pk_cols)
                    dest.execute(stmt)

                if len(pk_cols) == 1:
                    _fix_sequence(dest, table.name, pk_cols[0])

                print(f"{table.name}: synced {len(rows)} row(s)")


if __name__ == "__main__":
    try:
        sync()
    except SQLAlchemyError as exc:
        print(f"Postgres sync failed (will retry next scheduled run): {exc}", file=sys.stderr)
        sys.exit(1)
