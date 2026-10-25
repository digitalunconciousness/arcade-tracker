"""Indexes for the queries the pages run (Step 5.4).

PostgreSQL does not index a foreign key by itself, so every join and every "this machine's
orders" lookup scanned the whole table. At today's size that's invisible; play_record grows by
one row per machine per collection round, and the history only gets longer.

The list was taken from the SQL every page runs (each column a page filters, joins or sorts
on), plus every foreign key, so deletes that check for children stay quick. Where a page
filters on one column and sorts on another, one two-column index serves both, and covers
lookups on its first column alone.

Names follow ``ix_<table>_<columns>``. The migration that creates them
(``migrations/versions/c7d8e9f0a1b2_*``) keeps its own frozen copy of this list, and
tests/test_indexes.py checks the two agree.
"""
from __future__ import annotations

from app.extensions import db

INDEXES: dict[str, tuple[str, ...]] = {
    # A machine's plays by date (machine page, rankings); every machine's plays in a date range
    # (revenue, reports, graphs).
    "ix_play_record_game_id_date_recorded": ("play_record", "game_id", "date_recorded"),
    "ix_play_record_date_recorded": ("play_record", "date_recorded"),
    # A machine's orders, newest first; the maintenance report's date range; orders a trace
    # prompted.
    "ix_maintenance_record_game_id_date_reported": ("maintenance_record", "game_id",
                                                    "date_reported"),
    "ix_maintenance_record_date_reported": ("maintenance_record", "date_reported"),
    "ix_maintenance_record_rail_session_id": ("maintenance_record", "rail_session_id"),
    # A machine's rail history in time order; a device's sessions.
    "ix_rail_session_game_id_started": ("rail_session", "game_id", "started"),
    "ix_rail_session_device_id": ("rail_session", "device_id"),
    # A part's stock history, newest first; who changed stock.
    "ix_stock_history_item_id_timestamp": ("stock_history", "item_id", "timestamp"),
    "ix_stock_history_user_id": ("stock_history", "user_id"),
    # The rest are foreign keys: order pages, request pages, and deletes checking for children.
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


def attach() -> None:
    """Declare the indexes on the tables, so db.create_all() builds them too."""
    tables = db.metadata.tables
    for name, (table, *columns) in INDEXES.items():
        t = tables[table]
        if name not in {i.name for i in t.indexes}:
            db.Index(name, *(t.c[c] for c in columns))
