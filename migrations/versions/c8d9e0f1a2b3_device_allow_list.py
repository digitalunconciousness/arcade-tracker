"""The machines a GATBOX device may use (the device allow-list).

Adds ``device.all_machines`` (every existing device gets True: nothing changes on deploy) and
the ``device_machine`` table for a device limited to some machines.

Guarded like its neighbours. The column is added with a server default so existing rows are
filled, then the default is kept: a device row made by an older script still gets True.

Revision ID: c8d9e0f1a2b3
Revises: b6c7d8e9f0a1
"""

import sqlalchemy as sa
from alembic import op

revision = "c8d9e0f1a2b3"
down_revision = "b6c7d8e9f0a1"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def upgrade():
    if "all_machines" not in {c["name"] for c in _inspector().get_columns("device")}:
        op.add_column("device", sa.Column("all_machines", sa.Boolean(), nullable=False,
                                          server_default=sa.true()))
    if not _inspector().has_table("device_machine"):
        op.create_table(
            "device_machine",
            sa.Column("device_id", sa.Integer(),
                      sa.ForeignKey("device.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("game_id", sa.Integer(),
                      sa.ForeignKey("game.id", ondelete="CASCADE"), primary_key=True),
        )
        op.create_index("ix_device_machine_game_id", "device_machine", ["game_id"])


def downgrade():
    if _inspector().has_table("device_machine"):
        op.drop_table("device_machine")
    if "all_machines" in {c["name"] for c in _inspector().get_columns("device")}:
        with op.batch_alter_table("device") as batch:
            batch.drop_column("all_machines")
