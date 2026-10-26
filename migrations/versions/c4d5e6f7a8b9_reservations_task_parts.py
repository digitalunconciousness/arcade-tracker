"""Inventory meets work orders (inventory step 6): reservations and maintenance task parts.

Adds ``part_reservation`` (parts set aside for an open work order) and ``task_part`` (the
parts a maintenance task needs, reserved when it opens its order). No data moves. Guarded
like its neighbours, so a re-run is harmless.

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
"""

import sqlalchemy as sa
from alembic import op

revision = "c4d5e6f7a8b9"
down_revision = "b3c4d5e6f7a8"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def upgrade():
    if not _inspector().has_table("part_reservation"):
        op.create_table(
            "part_reservation",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("order_id", sa.Integer(),
                      sa.ForeignKey("maintenance_record.id", ondelete="CASCADE"),
                      nullable=False),
            sa.Column("item_id", sa.Integer(),
                      sa.ForeignKey("inventory_item.id", ondelete="CASCADE"), nullable=False),
            sa.Column("place_id", sa.Integer(),
                      sa.ForeignKey("stock_place.id", ondelete="SET NULL",
                                    name="fk_part_reservation_place_id"), nullable=True),
            sa.Column("quantity", sa.Integer(), nullable=False),
            sa.Column("created", sa.DateTime(), nullable=False),
            sa.Column("user_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL",
                                    name="fk_part_reservation_user_id"), nullable=True),
        )
        for column in ("order_id", "item_id", "place_id", "user_id"):
            op.create_index(f"ix_part_reservation_{column}", "part_reservation", [column])
    if not _inspector().has_table("task_part"):
        op.create_table(
            "task_part",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("task_id", sa.Integer(),
                      sa.ForeignKey("maintenance_task.id", ondelete="CASCADE"), nullable=False),
            sa.Column("item_id", sa.Integer(),
                      sa.ForeignKey("inventory_item.id", ondelete="CASCADE"), nullable=False),
            sa.Column("quantity", sa.Integer(), nullable=False),
            sa.UniqueConstraint("task_id", "item_id", name="uq_task_part"),
        )
        op.create_index("ix_task_part_task_id", "task_part", ["task_id"])
        op.create_index("ix_task_part_item_id", "task_part", ["item_id"])


def downgrade():
    for table in ("task_part", "part_reservation"):
        if _inspector().has_table(table):
            op.drop_table(table)
