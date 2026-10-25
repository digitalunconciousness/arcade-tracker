"""Application models — re-exported for convenient imports.

Usage::

    from app.models import User, Game, PlayRecord
"""

from app.models.device import Device
from app.models.game import Game, PlayRecord
from app.models.indexes import attach as _attach_indexes
from app.models.inventory import (
    InventoryItem,
    InventoryRequest,
    InventoryRequestHistory,
    LowStockAlert,
    MaintenanceInventoryUsage,
    StockHistory,
    item_game_compatibility,
)
from app.models.maintenance import MaintenanceRecord, WorkLog
from app.models.rail import RailSession, RailSessionTag, Reading
from app.models.user import User

_attach_indexes()

__all__ = [
    "User",
    "Game",
    "PlayRecord",
    "MaintenanceRecord",
    "WorkLog",
    "InventoryItem",
    "StockHistory",
    "LowStockAlert",
    "MaintenanceInventoryUsage",
    "InventoryRequest",
    "InventoryRequestHistory",
    "item_game_compatibility",
    "Device",
    "RailSession",
    "RailSessionTag",
    "Reading",
]
