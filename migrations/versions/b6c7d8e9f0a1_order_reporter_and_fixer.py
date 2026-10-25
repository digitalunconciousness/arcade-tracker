"""Who reported a work order and who fixed it (usability round).

Adds to ``maintenance_record``: ``reported_by`` (the name typed at a coin door),
``reported_by_id`` (the signed-in user who reported it) and ``fixed_by_id`` (who closed it as
Fixed). Existing orders keep NULL: who did them isn't known and isn't guessed; their free-text
technician still shows as who fixed them.

Guarded like its neighbours. Batch mode so SQLite gets the foreign keys too.

Revision ID: b6c7d8e9f0a1
Revises: a5b6c7d8e9f0
"""

import sqlalchemy as sa
from alembic import op

revision = "b6c7d8e9f0a1"
down_revision = "a5b6c7d8e9f0"
branch_labels = None
depends_on = None

USER_KEYS = ("reported_by_id", "fixed_by_id")


def _columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns("maintenance_record")}


def upgrade():
    have = _columns()
    if "reported_by" not in have:
        op.add_column("maintenance_record",
                      sa.Column("reported_by", sa.String(60), nullable=True))
    missing = [c for c in USER_KEYS if c not in have]
    if missing:
        with op.batch_alter_table("maintenance_record") as batch:
            for column in missing:
                batch.add_column(sa.Column(column, sa.Integer(), nullable=True))
                batch.create_foreign_key(f"fk_maintenance_record_{column}", "user",
                                         [column], ["id"], ondelete="SET NULL")
                batch.create_index(f"ix_maintenance_record_{column}", [column])


def downgrade():
    have = _columns()
    present = [c for c in USER_KEYS if c in have]
    if present:
        inspector = sa.inspect(op.get_bind())
        # The real names: a database built by create_all() may not use ours.
        keys = [fk["name"] for fk in inspector.get_foreign_keys("maintenance_record")
                if fk["constrained_columns"] and fk["constrained_columns"][0] in present
                and fk["name"]]
        indexes = [i["name"] for i in inspector.get_indexes("maintenance_record")
                   if i["column_names"] and i["column_names"][0] in present]
        with op.batch_alter_table("maintenance_record") as batch:
            for name in indexes:
                batch.drop_index(name)
            for name in keys:
                batch.drop_constraint(name, type_="foreignkey")
            for column in present:
                batch.drop_column(column)
    if "reported_by" in have:
        op.drop_column("maintenance_record", "reported_by")
