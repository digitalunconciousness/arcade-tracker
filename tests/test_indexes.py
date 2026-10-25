"""Query indexes (Step 5.4): declared once, built by both create_all() and the migration."""
from __future__ import annotations

import importlib.util
import os

import sqlalchemy as sa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")
REVISION, BEFORE = "c7d8e9f0a1b2", "b1c2d3e4f5a6"


def migration():
    path = os.path.join(MIGRATIONS, "versions", f"{REVISION}_add_query_indexes.py")
    spec = importlib.util.spec_from_file_location("query_indexes", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def live_indexes(engine) -> set[str]:
    inspector = sa.inspect(engine)
    return {i["name"] for t in inspector.get_table_names() for i in inspector.get_indexes(t)}


def test_the_migration_matches_the_models():
    """The migration keeps a frozen copy; if the models change, a new migration is due."""
    from app.models.indexes import INDEXES

    assert migration().INDEXES == INDEXES


def test_every_foreign_key_leads_an_index(app):
    """PostgreSQL won't index a foreign key by itself. A new model gets this check for free."""
    from app.extensions import db

    for table in db.metadata.tables.values():
        leading = {i.columns[0].name for i in table.indexes}
        leading |= {c.columns[0].name for c in table.constraints
                    if isinstance(c, (sa.PrimaryKeyConstraint, sa.UniqueConstraint)) and c.columns}
        leading |= {c.name for c in table.columns if c.unique}
        for fk in table.foreign_keys:
            assert fk.parent.name in leading, f"{table.name}.{fk.parent.name} has no index"


def test_create_all_builds_every_index(app):
    from app.extensions import db
    from app.models.indexes import INDEXES

    assert set(INDEXES) <= live_indexes(db.engine)


def test_the_migration_adds_and_removes_them(app):
    """Up from the previous revision, down again, and up a second time (it is idempotent)."""
    from flask_migrate import downgrade, stamp, upgrade

    from app.extensions import db
    from app.models.indexes import INDEXES

    for name, (table, *_c) in INDEXES.items():          # a database from before this step
        with db.engine.begin() as conn:
            conn.execute(sa.text(f"DROP INDEX IF EXISTS {name}"))
    assert not set(INDEXES) & live_indexes(db.engine)

    stamp(directory=MIGRATIONS, revision=BEFORE)
    upgrade(directory=MIGRATIONS, revision=REVISION)
    assert set(INDEXES) <= live_indexes(db.engine)

    upgrade(directory=MIGRATIONS, revision=REVISION)   # already there: nothing to do
    downgrade(directory=MIGRATIONS, revision=BEFORE)
    assert not set(INDEXES) & live_indexes(db.engine)
    upgrade(directory=MIGRATIONS, revision=REVISION)
    assert set(INDEXES) <= live_indexes(db.engine)
