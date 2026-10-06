"""The coin-door report token, and whether its label needs reprinting.

Phase 2.5: a maintenance request filed with no login by whoever can open the coin door.
Possession of ``game.report_token`` is what stands in for the physical key, which is why it
is a separate column and not ``barcode`` -- barcode is the public identifier, printed on the
cabinet labels and shared with GATBOX, and the roster slugs are guessable.

Hand-written and guarded per column, like d4e5f6a7b8c9 and for the same reason: the live
PostgreSQL arrived at its schema through migrations while a fresh test database is built by
``db.create_all()`` and stamped, so an unguarded ``add_column`` fails on the second.

``report_label_stale`` carries a server default because it is NOT NULL and the table already
has rows: without one, adding the column fails on a populated table.

Revision ID: e6f7a8b9c0d1
Revises: d4e5f6a7b8c9
"""

import sqlalchemy as sa
from alembic import op

revision = "e6f7a8b9c0d1"
down_revision = "d4e5f6a7b8c9"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _has_column(table: str, column: str) -> bool:
    if not _has_table(table):
        return False
    return column in {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if not _has_column("game", "report_token"):
        with op.batch_alter_table("game", schema=None) as batch_op:
            batch_op.add_column(sa.Column("report_token", sa.String(length=64), nullable=True))
            batch_op.create_unique_constraint(
                op.f("uq_game_report_token"), ["report_token"]
            )
    if not _has_column("game", "report_label_stale"):
        with op.batch_alter_table("game", schema=None) as batch_op:
            batch_op.add_column(sa.Column("report_label_stale", sa.Boolean(),
                                          nullable=False, server_default=sa.false()))


def downgrade():
    if _has_column("game", "report_label_stale"):
        with op.batch_alter_table("game", schema=None) as batch_op:
            batch_op.drop_column("report_label_stale")
    if _has_column("game", "report_token"):
        with op.batch_alter_table("game", schema=None) as batch_op:
            batch_op.drop_constraint(op.f("uq_game_report_token"), type_="unique")
            batch_op.drop_column("report_token")
