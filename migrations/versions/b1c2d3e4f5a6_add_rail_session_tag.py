"""Traces attached to a work order after it was raised.

Phase 6: a machine has an order open, someone meters it again at the bench, and the second
trace belongs on the order that exists rather than on a duplicate nobody asked for.

Deliberately *not* a replacement for ``maintenance_record.rail_session_id``, which stays what
contract v1 says it is -- the session that prompted the order. That column answers "why does
this order exist"; this table answers "what else has been measured since".

Hand-written and guarded, like d4e5f6a7b8c9 and e6f7a8b9c0d1 and for the same reason: the live
PostgreSQL arrived at its schema through migrations while a fresh test database is built by
``db.create_all()`` and stamped, so an unguarded ``create_table`` fails on the second.

Both foreign keys are indexed. The order page reads "every trace for this order", and the
session page will want "every order citing this trace".

Revision ID: b1c2d3e4f5a6
Revises: e6f7a8b9c0d1
"""

import sqlalchemy as sa
from alembic import op

revision = "b1c2d3e4f5a6"
down_revision = "e6f7a8b9c0d1"
branch_labels = None
depends_on = None


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def upgrade():
    if not _has_table("rail_session_tag"):
        op.create_table(
            "rail_session_tag",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("maintenance_record_id", sa.Integer(), nullable=False),
            sa.Column("rail_session_id", sa.Integer(), nullable=False),
            sa.Column("note", sa.Text(), nullable=True),
            sa.Column("source", sa.String(length=20), nullable=True),
            sa.Column("created", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(
                ["maintenance_record_id"], ["maintenance_record.id"],
                name=op.f("fk_rail_session_tag_maintenance_record_id"),
            ),
            sa.ForeignKeyConstraint(
                ["rail_session_id"], ["rail_session.id"],
                name=op.f("fk_rail_session_tag_rail_session_id"),
            ),
            sa.PrimaryKeyConstraint("id", name=op.f("pk_rail_session_tag")),
            sa.UniqueConstraint("maintenance_record_id", "rail_session_id",
                                name="uq_rail_session_tag_record_session"),
        )
        op.create_index(op.f("ix_rail_session_tag_maintenance_record_id"),
                        "rail_session_tag", ["maintenance_record_id"], unique=False)
        op.create_index(op.f("ix_rail_session_tag_rail_session_id"),
                        "rail_session_tag", ["rail_session_id"], unique=False)


def downgrade():
    if _has_table("rail_session_tag"):
        op.drop_index(op.f("ix_rail_session_tag_rail_session_id"),
                      table_name="rail_session_tag")
        op.drop_index(op.f("ix_rail_session_tag_maintenance_record_id"),
                      table_name="rail_session_tag")
        op.drop_table("rail_session_tag")
