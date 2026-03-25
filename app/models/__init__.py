"""Application models — re-exported for convenient imports.

Usage::

    from app.models import User, Game, PlayRecord
"""

from app.models.game import Game, PlayRecord
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
from app.models.user import User

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
]
