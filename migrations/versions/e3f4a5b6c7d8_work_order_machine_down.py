"""Whether a work order takes its machine out of play (feature step 2).

Adds ``maintenance_record.machine_down`` (True, False, or NULL for "never stated", which every
existing order is) and ``game_event.maintenance_id``, the order that made a status change.
Existing orders keep NULL: what they meant isn't known, so it isn't guessed, and an order that
never said never changes a machine's status.

Guarded like its neighbours: a column that already exists (create_all) is left alone. Batch
mode so SQLite, which can't add a foreign key with ALTER TABLE, gets the same schema.

Revision ID: e3f4a5b6c7d8
Revises: d1e2f3a4b5c6
"""

import sqlalchemy as sa
from alembic import op

revision = "e3f4a5b6c7d8"
down_revision = "d1e2f3a4b5c6"
branch_labels = None
depends_on = None


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if "machine_down" not in _columns("maintenance_record"):
        op.add_column("maintenance_record", sa.Column("machine_down", sa.Boolean(), nullable=True))
    if "maintenance_id" not in _columns("game_event"):
        with op.batch_alter_table("game_event") as batch:
            batch.add_column(sa.Column("maintenance_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_game_event_maintenance_id", "maintenance_record",
                                     ["maintenance_id"], ["id"], ondelete="SET NULL")
            batch.create_index("ix_game_event_maintenance_id", ["maintenance_id"])


def downgrade():
    if "maintenance_id" in _columns("game_event"):
        inspector = sa.inspect(op.get_bind())
        # The key's real name: a database built by create_all() may not use ours, and SQLite
        # may not name it at all (then dropping the column in batch mode takes it along).
        keys = [fk["name"] for fk in inspector.get_foreign_keys("game_event")
                if fk["constrained_columns"] == ["maintenance_id"] and fk["name"]]
        indexes = [i["name"] for i in inspector.get_indexes("game_event")
                   if i["column_names"] == ["maintenance_id"]]
        with op.batch_alter_table("game_event") as batch:
            for name in indexes:
                batch.drop_index(name)
            for name in keys:
                batch.drop_constraint(name, type_="foreignkey")
            batch.drop_column("maintenance_id")
    if "machine_down" in _columns("maintenance_record"):
        op.drop_column("maintenance_record", "machine_down")
