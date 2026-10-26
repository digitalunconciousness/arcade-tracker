"""Serialized spares (inventory step 4): parts tracked one by one.

Adds ``inventory_item.serialized`` (False for every part: nothing changes until someone turns
it on for a part), ``serial_unit`` (one row per unit: in a place, in a machine, out for repair
or retired) and ``unit_event`` (each unit's history). No data is moved. Guarded like its
neighbours, so a re-run is harmless.

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
"""

import sqlalchemy as sa
from alembic import op

revision = "a2b3c4d5e6f7"
down_revision = "f1a2b3c4d5e6"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def upgrade():
    if "serialized" not in {c["name"] for c in _inspector().get_columns("inventory_item")}:
        op.add_column("inventory_item", sa.Column("serialized", sa.Boolean(), nullable=False,
                                                  server_default=sa.false()))
    if not _inspector().has_table("serial_unit"):
        op.create_table(
            "serial_unit",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("item_id", sa.Integer(),
                      sa.ForeignKey("inventory_item.id", ondelete="CASCADE"), nullable=False),
            sa.Column("serial", sa.String(100), nullable=False),
            sa.Column("code", sa.String(16), nullable=False, unique=True),
            sa.Column("state", sa.String(20), nullable=False),
            sa.Column("place_id", sa.Integer(), sa.ForeignKey("stock_place.id"), nullable=True),
            sa.Column("game_id", sa.Integer(),
                      sa.ForeignKey("game.id", ondelete="SET NULL",
                                    name="fk_serial_unit_game_id"), nullable=True),
            sa.Column("repair_with", sa.String(200), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("created", sa.DateTime(), nullable=False),
            sa.UniqueConstraint("item_id", "serial", name="uq_serial_unit_item_serial"),
        )
        for column in ("item_id", "place_id", "game_id"):
            op.create_index(f"ix_serial_unit_{column}", "serial_unit", [column])
    if not _inspector().has_table("unit_event"):
        op.create_table(
            "unit_event",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("unit_id", sa.Integer(),
                      sa.ForeignKey("serial_unit.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(20), nullable=False),
            sa.Column("detail", sa.String(300), nullable=True),
            sa.Column("note", sa.String(500), nullable=True),
            sa.Column("order_id", sa.Integer(),
                      sa.ForeignKey("maintenance_record.id", ondelete="SET NULL",
                                    name="fk_unit_event_order_id"), nullable=True),
            sa.Column("user_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL",
                                    name="fk_unit_event_user_id"), nullable=True),
            sa.Column("at", sa.DateTime(), nullable=False),
        )
        for column in ("unit_id", "order_id", "user_id"):
            op.create_index(f"ix_unit_event_{column}", "unit_event", [column])


def downgrade():
    for table in ("unit_event", "serial_unit"):
        if _inspector().has_table(table):
            op.drop_table(table)
    if "serialized" in {c["name"] for c in _inspector().get_columns("inventory_item")}:
        with op.batch_alter_table("inventory_item") as batch:
            batch.drop_column("serialized")
