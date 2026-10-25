"""Preventive maintenance tasks (feature step 5).

Creates ``maintenance_task`` and adds ``maintenance_record.pm_task_id``, the task that raised an
order. No rows are written: there are no tasks until a manager sets one up, and every existing
order keeps NULL.

Guarded like its neighbours: what already exists (create_all) is left alone. Batch mode so
SQLite, which can't add a foreign key with ALTER TABLE, gets the same schema.

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
"""

import sqlalchemy as sa
from alembic import op

revision = "f4a5b6c7d8e9"
down_revision = "e3f4a5b6c7d8"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _columns(table: str) -> set[str]:
    return {c["name"] for c in _inspector().get_columns(table)}


def upgrade():
    if not _inspector().has_table("maintenance_task"):
        op.create_table(
            "maintenance_task",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("instructions", sa.Text(), nullable=True),
            sa.Column("every_plays", sa.Integer(), nullable=True),
            sa.Column("every_days", sa.Integer(), nullable=True),
            sa.Column("applies_to", sa.String(10), nullable=False),
            sa.Column("game_id", sa.Integer(),
                      sa.ForeignKey("game.id", ondelete="CASCADE"), nullable=True),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("created_by_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL"), nullable=True),
        )
        op.create_index("ix_maintenance_task_game_id", "maintenance_task", ["game_id"])
        op.create_index("ix_maintenance_task_created_by_id", "maintenance_task",
                        ["created_by_id"])
    if "pm_task_id" not in _columns("maintenance_record"):
        with op.batch_alter_table("maintenance_record") as batch:
            batch.add_column(sa.Column("pm_task_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_maintenance_record_pm_task_id", "maintenance_task",
                                     ["pm_task_id"], ["id"], ondelete="SET NULL")
            batch.create_index("ix_maintenance_record_pm_task_id", ["pm_task_id"])


def downgrade():
    if "pm_task_id" in _columns("maintenance_record"):
        inspector = _inspector()
        # The real names: a database built by create_all() may not use ours, and SQLite may not
        # name the key at all (then dropping the column in batch mode takes it along).
        keys = [fk["name"] for fk in inspector.get_foreign_keys("maintenance_record")
                if fk["constrained_columns"] == ["pm_task_id"] and fk["name"]]
        indexes = [i["name"] for i in inspector.get_indexes("maintenance_record")
                   if i["column_names"] == ["pm_task_id"]]
        with op.batch_alter_table("maintenance_record") as batch:
            for name in indexes:
                batch.drop_index(name)
            for name in keys:
                batch.drop_constraint(name, type_="foreignkey")
            batch.drop_column("pm_task_id")
    if _inspector().has_table("maintenance_task"):
        op.drop_table("maintenance_task")
