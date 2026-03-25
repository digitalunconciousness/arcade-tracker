"""Inventory, stock-history, and request models."""

from __future__ import annotations

from datetime import datetime, timezone

from app.extensions import db


# ---------------------------------------------------------------------------
# Association table – many-to-many between InventoryItem and Game
# ---------------------------------------------------------------------------
item_game_compatibility = db.Table(
    "item_game_compatibility",
    db.Column(
        "item_id",
        db.Integer,
        db.ForeignKey("inventory_item.id"),
        primary_key=True,
    ),
    db.Column(
        "game_id",
        db.Integer,
        db.ForeignKey("game.id"),
        primary_key=True,
    ),
)


class InventoryItem(db.Model):
    """A trackable inventory / spare-parts item."""

    __tablename__ = "inventory_item"

    id: int = db.Column(db.Integer, primary_key=True)
    name: str = db.Column(db.String(200), nullable=False)
    description: str | None = db.Column(db.Text, nullable=True)
    stock_quantity: int = db.Column(db.Integer, default=0)
    unit_price: float = db.Column(db.Float, default=0.0)
    minimum_stock: int = db.Column(db.Integer, default=5)
    supplier: str | None = db.Column(db.String(200), nullable=True)
    part_number: str | None = db.Column(db.String(100), nullable=True)
    date_added: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    last_restocked: datetime | None = db.Column(db.DateTime, nullable=True)
    notes: str | None = db.Column(db.Text, nullable=True)

    # Relationships
    compatible_games = db.relationship(
        "Game", secondary=item_game_compatibility, backref="compatible_items"
    )
    stock_history = db.relationship(
        "StockHistory", backref="item", lazy=True, cascade="all, delete-orphan"
    )

    def is_low_stock(self) -> bool:
        """Return ``True`` when quantity is at or below the minimum."""
        return self.stock_quantity <= self.minimum_stock

    def total_value(self) -> float:
        """Compute total on-hand value."""
        return self.stock_quantity * self.unit_price

    def __repr__(self) -> str:
        return f"<InventoryItem {self.name!r} qty={self.stock_quantity}>"


class StockHistory(db.Model):
    """An auditable record of stock-level changes."""

    __tablename__ = "stock_history"

    id: int = db.Column(db.Integer, primary_key=True)
    item_id: int = db.Column(
        db.Integer, db.ForeignKey("inventory_item.id"), nullable=False
    )
    change_type: str = db.Column(db.String(20), nullable=False)
    quantity_change: int = db.Column(db.Integer, nullable=False)
    previous_quantity: int = db.Column(db.Integer, nullable=False)
    new_quantity: int = db.Column(db.Integer, nullable=False)
    reason: str | None = db.Column(db.String(200), nullable=True)
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    user_id: int = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )

    user = db.relationship("User", backref="stock_changes")

    def __repr__(self) -> str:
        return (
            f"<StockHistory item_id={self.item_id} "
            f"change={self.quantity_change:+d}>"
        )


class LowStockAlert(db.Model):
    """Alert raised when an item drops to or below minimum stock."""

    __tablename__ = "low_stock_alert"

    id: int = db.Column(db.Integer, primary_key=True)
    item_id: int = db.Column(
        db.Integer, db.ForeignKey("inventory_item.id"), nullable=False
    )
    alert_triggered: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    email_sent: bool = db.Column(db.Boolean, default=False)
    resolved: bool = db.Column(db.Boolean, default=False)
    resolved_date: datetime | None = db.Column(db.DateTime, nullable=True)

    item = db.relationship("InventoryItem", backref="alerts")

    def __repr__(self) -> str:
        return f"<LowStockAlert item_id={self.item_id} resolved={self.resolved}>"


class MaintenanceInventoryUsage(db.Model):
    """Parts consumed during a maintenance event."""

    __tablename__ = "maintenance_inventory_usage"

    id: int = db.Column(db.Integer, primary_key=True)
    maintenance_id: int = db.Column(
        db.Integer, db.ForeignKey("maintenance_record.id"), nullable=False
    )
    item_id: int = db.Column(
        db.Integer, db.ForeignKey("inventory_item.id"), nullable=False
    )
    quantity_used: int = db.Column(db.Integer, nullable=False)
    unit_price_at_time: float = db.Column(db.Float, nullable=False)
    total_cost: float = db.Column(db.Float, nullable=False)
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    maintenance_record = db.relationship(
        "MaintenanceRecord", backref="inventory_usage"
    )
    item = db.relationship("InventoryItem", backref="maintenance_usage")

    def __repr__(self) -> str:
        return (
            f"<MaintenanceInventoryUsage maintenance_id={self.maintenance_id} "
            f"item_id={self.item_id}>"
        )


class InventoryRequest(db.Model):
    """A request to order / restock an inventory item."""

    __tablename__ = "inventory_request"

    id: int = db.Column(db.Integer, primary_key=True)
    item_id: int | None = db.Column(
        db.Integer, db.ForeignKey("inventory_item.id"), nullable=True
    )
    maintenance_id: int | None = db.Column(
        db.Integer, db.ForeignKey("maintenance_record.id"), nullable=True
    )
    item_name: str = db.Column(db.String(200), nullable=False)
    quantity_requested: int = db.Column(db.Integer, nullable=False)
    reason: str | None = db.Column(db.Text, nullable=True)
    urgency: str = db.Column(db.String(20), default="Normal")
    status: str = db.Column(db.String(20), default="Pending")
    requested_by_id: int = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    date_requested: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    date_fulfilled: datetime | None = db.Column(db.DateTime, nullable=True)
    notes: str | None = db.Column(db.Text, nullable=True)
    tracking_number: str | None = db.Column(db.String(200), nullable=True)
    vendor: str | None = db.Column(db.String(200), nullable=True)
    estimated_arrival = db.Column(db.Date, nullable=True)
    carrier: str | None = db.Column(db.String(50), nullable=True)
    tracking_status: str | None = db.Column(db.String(50), nullable=True)
    tracking_details: str | None = db.Column(db.Text, nullable=True)
    last_tracking_update: datetime | None = db.Column(
        db.DateTime, nullable=True
    )

    # Relationships
    requested_by = db.relationship("User", backref="inventory_requests")
    item = db.relationship("InventoryItem", backref="requests")
    maintenance_record = db.relationship(
        "MaintenanceRecord", backref="inventory_requests"
    )
    history = db.relationship(
        "InventoryRequestHistory",
        backref="request",
        lazy=True,
        cascade="all, delete-orphan",
        order_by="InventoryRequestHistory.timestamp.desc()",
    )

    def __repr__(self) -> str:
        return f"<InventoryRequest id={self.id} status={self.status!r}>"


class InventoryRequestHistory(db.Model):
    """Audit trail for changes made to an inventory request."""

    __tablename__ = "inventory_request_history"

    id: int = db.Column(db.Integer, primary_key=True)
    request_id: int = db.Column(
        db.Integer, db.ForeignKey("inventory_request.id"), nullable=False
    )
    user_id: int = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )
    action: str = db.Column(db.String(50), nullable=False)
    field_changed: str | None = db.Column(db.String(50), nullable=True)
    old_value: str | None = db.Column(db.String(500), nullable=True)
    new_value: str | None = db.Column(db.String(500), nullable=True)
    notes: str | None = db.Column(db.Text, nullable=True)
    timestamp: datetime = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    user = db.relationship("User", backref="request_history_actions")

    def __repr__(self) -> str:
        return (
            f"<InventoryRequestHistory request_id={self.request_id} "
            f"action={self.action!r}>"
        )
