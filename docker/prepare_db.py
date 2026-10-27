"""Get the database ready before the container serves anything.

- Waits for the database to answer (PostgreSQL starts alongside the app in docker-compose).
- A new, empty database gets every table with ``create_all`` and is stamped at the newest
  migration: the migrations add to an existing schema and can't build one from nothing.
- An existing one is upgraded with the migrations, as ``deploy/deploy.sh`` does on a server.
"""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sqlalchemy as sa
from flask_migrate import stamp, upgrade

from app import create_app
from app.extensions import db

MIGRATIONS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations")
WAIT_S = 60


def wait_for_database() -> None:
    deadline = time.monotonic() + WAIT_S
    while True:
        try:
            with db.engine.connect() as conn:
                conn.execute(sa.text("SELECT 1"))
            return
        except sa.exc.OperationalError as exc:
            if time.monotonic() > deadline:
                sys.exit(f"The database didn't answer in {WAIT_S} s: {exc}")
            print("Waiting for the database...", flush=True)
            time.sleep(2)


def main() -> None:
    app = create_app()
    with app.app_context():
        wait_for_database()
        tables = sa.inspect(db.engine).get_table_names()
        if "user" not in tables:
            print("New database: creating the tables.", flush=True)
            db.create_all()
            stamp(directory=MIGRATIONS, revision="head")
        elif "alembic_version" not in tables:
            sys.exit("The database has tables but no migration stamp. Check it with "
                     "scripts/check_schema.py before going on (see deploy/RUNBOOK.md).")
        else:
            print("Existing database: applying any new migrations.", flush=True)
            upgrade(directory=MIGRATIONS)


if __name__ == "__main__":
    main()
