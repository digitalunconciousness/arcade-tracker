"""Alerts (feature step 6): channels, the outbox, and small settings.

Creates ``alert_channel``, ``alert`` and ``app_setting``. No rows: nothing is sent until an
admin sets up a channel.

Guarded like its neighbours: a table that already exists (create_all) is left alone.

Revision ID: a5b6c7d8e9f0
Revises: f4a5b6c7d8e9
"""

import sqlalchemy as sa
from alembic import op

revision = "a5b6c7d8e9f0"
down_revision = "f4a5b6c7d8e9"
branch_labels = None
depends_on = None


def _has(table: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(table)


def upgrade():
    if not _has("alert_channel"):
        op.create_table(
            "alert_channel",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(60), nullable=False),
            sa.Column("ntfy_url", sa.String(500), nullable=True),
            sa.Column("ntfy_token", sa.String(200), nullable=True),
            sa.Column("discord_webhook", sa.String(500), nullable=True),
            sa.Column("events", sa.Text(), nullable=False),
            sa.Column("quiet", sa.Boolean(), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
        )
    if not _has("alert"):
        op.create_table(
            "alert",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("channel_id", sa.Integer(),
                      sa.ForeignKey("alert_channel.id", ondelete="CASCADE"), nullable=False),
            sa.Column("target", sa.String(10), nullable=False),
            sa.Column("event", sa.String(20), nullable=False),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("path", sa.String(300), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("status", sa.String(10), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False),
            sa.Column("next_try_at", sa.DateTime(), nullable=True),
            sa.Column("sent_at", sa.DateTime(), nullable=True),
            sa.Column("error", sa.String(300), nullable=True),
        )
        op.create_index("ix_alert_channel_id", "alert", ["channel_id"])
        op.create_index("ix_alert_status_next_try_at", "alert", ["status", "next_try_at"])
    if not _has("app_setting"):
        op.create_table(
            "app_setting",
            sa.Column("key", sa.String(50), primary_key=True),
            sa.Column("value", sa.Text(), nullable=True),
        )


def downgrade():
    for table in ("app_setting", "alert", "alert_channel"):
        if _has(table):
            op.drop_table(table)
