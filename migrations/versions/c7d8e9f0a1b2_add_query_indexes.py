"""Indexes for the queries the pages run (Step 5.4).

PostgreSQL indexes no foreign key by itself, so every join and every "this machine's orders"
lookup scanned its table. See app/models/indexes.py for why each one is here.

The list is a frozen copy of ``app.models.indexes.INDEXES`` as of this revision: a migration
must keep meaning what it meant when it was written, whatever the app's code says later.
tests/test_indexes.py checks the two still agree.

Hand-written and guarded, like b1c2d3e4f5a6: a fresh test database is built by
``db.create_all()`` (which now creates these) and then stamped, while the live PostgreSQL gets
them here. An index that already exists is left alone.

Plain CREATE INDEX, not CONCURRENTLY. deploy.sh migrates while the old version is still
serving, and CREATE INDEX blocks writes to its table while it builds -- but the largest table
holds a few thousand rows, so each one takes milliseconds. CONCURRENTLY would need to run
outside the migration's transaction, which is more to go wrong than this is worth.

Revision ID: c7d8e9f0a1b2
Revises: b1c2d3e4f5a6
"""

import sqlalchemy as sa
from alembic import op

revision = "c7d8e9f0a1b2"
down_revision = "b1c2d3e4f5a6"
branch_labels = None
depends_on = None

INDEXES = {
    "ix_play_record_game_id_date_recorded": ("play_record", "game_id", "date_recorded"),
    "ix_play_record_date_recorded": ("play_record", "date_recorded"),
    "ix_maintenance_record_game_id_date_reported": ("maintenance_record", "game_id",
                                                    "date_reported"),
    "ix_maintenance_record_date_reported": ("maintenance_record", "date_reported"),
    "ix_maintenance_record_rail_session_id": ("maintenance_record", "rail_session_id"),
    "ix_rail_session_game_id_started": ("rail_session", "game_id", "started"),
    "ix_rail_session_device_id": ("rail_session", "device_id"),
    "ix_stock_history_item_id_timestamp": ("stock_history", "item_id", "timestamp"),
    "ix_stock_history_user_id": ("stock_history", "user_id"),
    "ix_work_log_maintenance_id": ("work_log", "maintenance_id"),
    "ix_work_log_user_id": ("work_log", "user_id"),
    "ix_inventory_request_requested_by_id": ("inventory_request", "requested_by_id"),
    "ix_inventory_request_item_id": ("inventory_request", "item_id"),
    "ix_inventory_request_maintenance_id": ("inventory_request", "maintenance_id"),
    "ix_inventory_request_history_request_id": ("inventory_request_history", "request_id"),
    "ix_inventory_request_history_user_id": ("inventory_request_history", "user_id"),
    "ix_maintenance_inventory_usage_maintenance_id": ("maintenance_inventory_usage",
                                                      "maintenance_id"),
    "ix_maintenance_inventory_usage_item_id": ("maintenance_inventory_usage", "item_id"),
    "ix_low_stock_alert_item_id": ("low_stock_alert", "item_id"),
    "ix_item_game_compatibility_game_id": ("item_game_compatibility", "game_id"),
}


def _existing(table: str) -> set[str]:
    return {i["name"] for i in sa.inspect(op.get_bind()).get_indexes(table)}


def upgrade():
    for name, (table, *columns) in INDEXES.items():
        if name not in _existing(table):
            op.create_index(name, table, columns, unique=False)


def downgrade():
    for name, (table, *_columns) in reversed(list(INDEXES.items())):
        if name in _existing(table):
            op.drop_index(name, table_name=table)
