"""A machine's location and status over time (feature step 1).

Creates ``game_event`` and gives every existing machine two ``baseline`` rows: its location and
its status as they are now, dated now. A baseline means "tracked from here", not "arrived here
then": when a machine really moved isn't recorded anywhere, so it isn't guessed (not even from
``date_added``). From here on every change is recorded as it happens (app/services/history.py).

Hand-written and guarded, like b1c2d3e4f5a6 and c7d8e9f0a1b2: a test database built by
``db.create_all()`` and stamped already has the table, and a machine that already has events
gets no baseline, so running this twice adds nothing.

Revision ID: d1e2f3a4b5c6
Revises: c7d8e9f0a1b2
"""

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "d1e2f3a4b5c6"
down_revision = "c7d8e9f0a1b2"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade():
    if not _has_table("game_event"):
        op.create_table(
            "game_event",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("game_id", sa.Integer(), nullable=False),
            sa.Column("kind", sa.String(length=10), nullable=False),
            sa.Column("old_value", sa.String(length=20), nullable=True),
            sa.Column("new_value", sa.String(length=20), nullable=False),
            sa.Column("occurred_at", sa.DateTime(), nullable=False),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("source", sa.String(length=10), nullable=False),
            sa.ForeignKeyConstraint(["game_id"], ["game.id"], ondelete="CASCADE",
                                    name=op.f("fk_game_event_game_id")),
            sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="SET NULL",
                                    name=op.f("fk_game_event_user_id")),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_game_event")),
        )
        op.create_index("ix_game_event_game_id_occurred_at", "game_event",
                        ["game_id", "occurred_at"], unique=False)
        op.create_index("ix_game_event_user_id", "game_event", ["user_id"], unique=False)

    now = datetime.now(UTC).replace(tzinfo=None)
    for kind, fallback in (("location", "Warehouse"), ("status", "Working")):
        op.get_bind().execute(sa.text(f"""
            INSERT INTO game_event (game_id, kind, old_value, new_value, occurred_at, user_id, source)
            SELECT g.id, :kind, NULL, COALESCE(g.{kind}, :fallback), :now, NULL, 'baseline'
            FROM game g
            WHERE NOT EXISTS (SELECT 1 FROM game_event e WHERE e.game_id = g.id AND e.kind = :kind)
        """), {"kind": kind, "fallback": fallback, "now": now})


def downgrade():
    if _has_table("game_event"):
        op.drop_index("ix_game_event_user_id", table_name="game_event")
        op.drop_index("ix_game_event_game_id_occurred_at", table_name="game_event")
        op.drop_table("game_event")
