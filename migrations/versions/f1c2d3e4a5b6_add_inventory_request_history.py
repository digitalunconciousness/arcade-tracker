"""create inventory_request_history

The InventoryRequestHistory model was added without a migration, so the table
only ever existed on databases built by ``db.create_all()`` (or the legacy
``create_request_history_table.py``). A database brought up through Flask-Migrate
did not have it, and any page touching the audit trail failed with
``no such table: inventory_request_history``.

This creates it when it is absent and does nothing when it is already there, so
it is safe both on a migration-built database and on one that ``create_all``
already populated.

Revision ID: f1c2d3e4a5b6
Revises: c1a2b3d4e5f6
Create Date: 2026-09-30

"""
import sqlalchemy as sa
from alembic import op

revision = "f1c2d3e4a5b6"
down_revision = "c1a2b3d4e5f6"
branch_labels = None
depends_on = None

TABLE = "inventory_request_history"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade():
    if _has_table(TABLE):
        return
    op.create_table(
        TABLE,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("request_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("field_changed", sa.String(length=50), nullable=True),
        sa.Column("old_value", sa.String(length=500), nullable=True),
        sa.Column("new_value", sa.String(length=500), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["request_id"], ["inventory_request.id"],
                                name=op.f("fk_inventory_request_history_request_id")),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"],
                                name=op.f("fk_inventory_request_history_user_id")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_inventory_request_history")),
    )


def downgrade():
    if _has_table(TABLE):
        op.drop_table(TABLE)
