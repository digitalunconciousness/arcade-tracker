#!/usr/bin/env python3
"""Copy a recovered SQLite snapshot into the live PostgreSQL database.

Data-only: the target schema must already exist (it was built by ``create_all``).
Tables are filled in foreign-key order, only the columns both sides share are
copied, and the ``user`` rows are inserted with fresh ids so an account that
already exists in the target is kept. Rows pointing at a user are remapped to
the new ids. Sequences are reset afterwards.

Refuses to run if any target table other than ``user`` already holds rows, so it
cannot double-insert.

    python restore_from_sqlite.py <snapshot.db> [--commit]

Without ``--commit`` it is a dry run: everything is done inside a transaction
that is rolled back, and the counts it reports are what a real run would give.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys

import sqlalchemy as sa

# Parents before children. Tables not listed here are not copied.
ORDER = [
    "game",
    "inventory_item",
    "user",
    "maintenance_record",
    "play_record",
    "inventory_request",
    "stock_history",
    "work_log",
    "maintenance_inventory_usage",
    "item_game_compatibility",
    "low_stock_alert",
]

# Columns that reference user.id and therefore need remapping.
USER_REFS = {
    "inventory_request": ["user_id"],
    "stock_history": ["user_id"],
    "work_log": ["user_id"],
}


def quote(name: str) -> str:
    return f'"{name}"'


def sqlite_columns(cur, table: str) -> list[str]:
    return [r[1] for r in cur.execute(f'PRAGMA table_info("{table}")')]


def pg_columns(conn, table: str) -> list[str]:
    return list(pg_types(conn, table))


def pg_types(conn, table: str) -> dict[str, str]:
    """{column: data_type} for *table*, in declaration order."""
    rows = conn.execute(
        sa.text(
            "SELECT column_name, data_type FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=:t ORDER BY ordinal_position"
        ),
        {"t": table},
    )
    return {r[0]: r[1] for r in rows}


def coerce(value, data_type: str):
    """SQLite is loosely typed; PostgreSQL is not. Convert where it matters.

    SQLite keeps booleans as 0/1 integers, which PostgreSQL rejects for a
    ``boolean`` column ("is of type boolean but expression is of type integer").
    """
    if value is None:
        return None
    if data_type == "boolean" and not isinstance(value, bool):
        return bool(value)
    return value


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("snapshot")
    p.add_argument("--commit", action="store_true", help="actually write (default: dry run)")
    p.add_argument("--url", default=os.environ.get("DATABASE_URL"))
    args = p.parse_args()

    if not args.url:
        print("DATABASE_URL is not set and --url was not given", file=sys.stderr)
        return 2
    if not os.path.exists(args.snapshot):
        print(f"no such snapshot: {args.snapshot}", file=sys.stderr)
        return 2

    lite = sqlite3.connect(f"file:{args.snapshot}?mode=ro", uri=True)
    lite.row_factory = sqlite3.Row
    cur = lite.cursor()
    engine = sa.create_engine(args.url)

    with engine.begin() as conn:
        # 1. Safety: nothing but `user` may already hold rows.
        occupied = []
        for t in ORDER:
            if t == "user":
                continue
            n = conn.execute(sa.text(f"SELECT COUNT(*) FROM {quote(t)}")).scalar()
            if n:
                occupied.append(f"{t}={n}")
        if occupied:
            print("REFUSING: target already has rows in: " + ", ".join(occupied), file=sys.stderr)
            print("This script only fills an empty database.", file=sys.stderr)
            return 1

        # 2. Users first, with fresh ids, so existing accounts survive.
        existing_names = {
            r[0] for r in conn.execute(sa.text('SELECT username FROM "user"'))
        }
        next_id = (conn.execute(sa.text('SELECT COALESCE(MAX(id), 0) FROM "user"')).scalar()) + 1
        user_map: dict[int, int] = {}
        user_types = pg_types(conn, "user")
        shared_user_cols = [c for c in sqlite_columns(cur, "user") if c in user_types]
        copy_cols = [c for c in shared_user_cols if c != "id"]
        skipped_users = []
        for row in cur.execute('SELECT * FROM "user"'):
            if row["username"] in existing_names:
                skipped_users.append(row["username"])
                continue
            vals = {c: coerce(row[c], user_types[c]) for c in copy_cols}
            vals["id"] = next_id
            cols = ", ".join(quote(c) for c in ["id"] + copy_cols)
            binds = ", ".join(f":{c}" for c in ["id"] + copy_cols)
            conn.execute(sa.text(f'INSERT INTO "user" ({cols}) VALUES ({binds})'), vals)
            user_map[row["id"]] = next_id
            next_id += 1

        # 3. Everything else, keeping original ids (these tables are empty).
        counts: dict[str, int] = {}
        dropped: dict[str, list[str]] = {}
        for table in ORDER:
            if table == "user":
                continue
            lite_cols = sqlite_columns(cur, table)
            target_types = pg_types(conn, table)
            shared = [c for c in lite_cols if c in target_types]
            gone = [c for c in lite_cols if c not in target_types]
            if gone:
                dropped[table] = gone
            n = 0
            for row in cur.execute(f'SELECT * FROM "{table}"'):
                vals = {c: coerce(row[c], target_types[c]) for c in shared}
                for ref in USER_REFS.get(table, []):
                    if ref in vals and vals[ref] is not None:
                        vals[ref] = user_map.get(vals[ref], vals[ref])
                cols = ", ".join(quote(c) for c in shared)
                binds = ", ".join(f":{c}" for c in shared)
                conn.execute(sa.text(f"INSERT INTO {quote(table)} ({cols}) VALUES ({binds})"), vals)
                n += 1
            counts[table] = n

        # 4. Reset sequences so new inserts don't collide.
        resets = []
        for table in ORDER:
            # Association tables (composite primary key) have no id column.
            if "id" not in pg_types(conn, table):
                continue
            seq = conn.execute(
                sa.text("SELECT pg_get_serial_sequence(:t, 'id')"), {"t": table}
            ).scalar()
            if not seq:
                continue
            conn.execute(
                sa.text(
                    f"SELECT setval('{seq}', GREATEST((SELECT COALESCE(MAX(id), 0) FROM {quote(table)}), 1))"
                )
            )
            resets.append(table)

        # 5. Report.
        print("users inserted :", len(user_map), f"(skipped, name already present: {skipped_users or 'none'})")
        for t in ORDER:
            if t == "user":
                continue
            print(f"  {t:<30} {counts[t]}")
        if dropped:
            print("columns in the snapshot with no column in the target (not copied):")
            for t, cols in dropped.items():
                print(f"  {t}: {', '.join(cols)}")
        print("sequences reset :", len(resets))

        if not args.commit:
            print("\nDRY RUN - rolling back. Re-run with --commit to keep it.")
            raise _Rollback()
    return 0


class _Rollback(Exception):
    pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except _Rollback:
        sys.exit(0)
