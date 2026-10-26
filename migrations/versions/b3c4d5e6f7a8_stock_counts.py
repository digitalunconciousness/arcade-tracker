"""Planned counts (inventory step 5): full and cycle counts, reviewed before applying.

Adds ``stock_count`` and ``stock_count_line``. No data moves; quick count mode on a place's
page is unchanged. Guarded like its neighbours, so a re-run is harmless.

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
"""

import sqlalchemy as sa
from alembic import op

revision = "b3c4d5e6f7a8"
down_revision = "a2b3c4d5e6f7"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def upgrade():
    if not _inspector().has_table("stock_count"):
        op.create_table(
            "stock_count",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("kind", sa.String(10), nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("due", sa.Date(), nullable=True),
            sa.Column("repeat_days", sa.Integer(), nullable=True),
            sa.Column("cycle_size", sa.Integer(), nullable=True),
            sa.Column("place_ids", sa.String(500), nullable=True),
            sa.Column("created_by_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL",
                                    name="fk_stock_count_created_by_id"), nullable=True),
            sa.Column("created", sa.DateTime(), nullable=False),
            sa.Column("applied", sa.DateTime(), nullable=True),
            sa.Column("applied_by_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL",
                                    name="fk_stock_count_applied_by_id"), nullable=True),
        )
        op.create_index("ix_stock_count_created_by_id", "stock_count", ["created_by_id"])
        op.create_index("ix_stock_count_applied_by_id", "stock_count", ["applied_by_id"])
    if not _inspector().has_table("stock_count_line"):
        op.create_table(
            "stock_count_line",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("count_id", sa.Integer(),
                      sa.ForeignKey("stock_count.id", ondelete="CASCADE"), nullable=False),
            sa.Column("item_id", sa.Integer(),
                      sa.ForeignKey("inventory_item.id", ondelete="CASCADE"), nullable=False),
            sa.Column("place_id", sa.Integer(), sa.ForeignKey("stock_place.id"),
                      nullable=False),
            sa.Column("expected", sa.Integer(), nullable=False),
            sa.Column("counted", sa.Integer(), nullable=True),
            sa.Column("counted_by_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL",
                                    name="fk_stock_count_line_counted_by_id"), nullable=True),
            sa.Column("counted_at", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("count_id", "item_id", "place_id", name="uq_stock_count_line"),
        )
        for column in ("count_id", "item_id", "place_id", "counted_by_id"):
            op.create_index(f"ix_stock_count_line_{column}", "stock_count_line", [column])


def downgrade():
    for table in ("stock_count_line", "stock_count"):
        if _inspector().has_table(table):
            op.drop_table(table)
