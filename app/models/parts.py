"""Part details (inventory step 2): categories, suppliers, and the price log.

The part itself stays ``InventoryItem``. Its ``unit_price`` keeps its meaning, the cost a
work order is charged, so reports don't change; a supplier's price is what that supplier
charges. ``PriceChange`` records every change to either, whatever made it.
"""

from __future__ import annotations

from datetime import UTC, datetime

from app.extensions import db

# The categories a new install starts with (owner's choice, 2026-10-26). Managers edit the
# list; the migration seeds it once.
DEFAULT_CATEGORIES = (
    "Switches & buttons", "Coin & token mechs", "Lamps & LEDs", "Fuses & electrical",
    "Boards & power supplies", "Joysticks & controls", "Belts & mechanical",
    "Cleaning & consumables", "Tickets & prizes",
)
# Offered when typing a unit; any short word is allowed.
UNITS = ("each", "pair", "set", "pack", "box", "bag", "roll", "foot", "metre", "litre")


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class PartCategory(db.Model):
    __tablename__ = "part_category"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(60), nullable=False, unique=True)

    def __repr__(self) -> str:
        return f"<PartCategory {self.name!r}>"


class Supplier(db.Model):
    """Someone parts are bought from."""

    __tablename__ = "supplier"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False, unique=True)
    website = db.Column(db.String(300), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    account_number = db.Column(db.String(100), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    archived = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self) -> str:
        return f"<Supplier {self.name!r}>"


class ItemSupplier(db.Model):
    """One supplier for one part: their part number, price, pack and link."""

    __tablename__ = "item_supplier"
    __table_args__ = (db.UniqueConstraint("item_id", "supplier_id",
                                          name="uq_item_supplier_item_supplier"),)

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_item.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey("supplier.id"), nullable=False,
                            index=True)
    supplier_part_number = db.Column(db.String(100), nullable=True)
    price = db.Column(db.Float, nullable=True)          # per pack when pack_size is set
    pack_size = db.Column(db.Integer, nullable=True)
    url = db.Column(db.String(500), nullable=True)
    preferred = db.Column(db.Boolean, nullable=False, default=False)

    item = db.relationship("InventoryItem",
                           backref=db.backref("suppliers", cascade="all, delete-orphan"))
    supplier = db.relationship("Supplier", backref="parts")

    @property
    def unit_cost(self) -> float | None:
        """The price of one unit, for comparing suppliers who sell in different packs."""
        if self.price is None:
            return None
        return self.price / (self.pack_size or 1)


class PriceChange(db.Model):
    """One change to a price: the part's own (supplier is null) or a supplier's. Only ever
    added to."""

    __tablename__ = "price_change"

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_item.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey("supplier.id", ondelete="SET NULL",
                                                      name="fk_price_change_supplier_id"),
                            nullable=True, index=True)
    old_price = db.Column(db.Float, nullable=True)
    new_price = db.Column(db.Float, nullable=True)
    reason = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL",
                                                  name="fk_price_change_user_id"),
                        nullable=True, index=True)
    changed = db.Column(db.DateTime, nullable=False, default=_now)

    item = db.relationship("InventoryItem",
                           backref=db.backref("price_changes", cascade="all, delete-orphan",
                                              order_by="PriceChange.id.desc()"))
    supplier = db.relationship("Supplier")
    user = db.relationship("User")


# --- purchasing (inventory step 3) ---------------------------------------------------------

PO_STATUSES = ("Draft", "Sent", "Partly received", "Received", "Cancelled")
PO_OPEN = ("Draft", "Sent", "Partly received")


class PurchaseOrder(db.Model):
    """An order to one supplier, for arcades that want them (a setting; off by default).
    Lines are in the part's unit; a delivery can come in pieces."""

    __tablename__ = "purchase_order"

    id = db.Column(db.Integer, primary_key=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey("supplier.id"), nullable=False,
                            index=True)
    status = db.Column(db.String(20), nullable=False, default="Draft")
    notes = db.Column(db.Text, nullable=True)
    expected = db.Column(db.Date, nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL",
                                                        name="fk_purchase_order_created_by_id"),
                              nullable=True, index=True)
    created = db.Column(db.DateTime, nullable=False, default=_now)
    sent = db.Column(db.DateTime, nullable=True)
    closed = db.Column(db.DateTime, nullable=True)

    supplier = db.relationship("Supplier", backref="orders")
    created_by = db.relationship("User")
    lines = db.relationship("PurchaseOrderLine", backref="order",
                            cascade="all, delete-orphan", order_by="PurchaseOrderLine.id")

    @property
    def is_open(self) -> bool:
        return self.status in PO_OPEN

    @property
    def total(self) -> float:
        return sum(line.cost for line in self.lines)


class PurchaseOrderLine(db.Model):
    __tablename__ = "purchase_order_line"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("purchase_order.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_item.id"), nullable=False,
                        index=True)
    quantity = db.Column(db.Integer, nullable=False)            # in the part's unit
    unit_price = db.Column(db.Float, nullable=True)             # per unit
    quantity_received = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    item = db.relationship("InventoryItem", backref="order_lines")

    @property
    def outstanding(self) -> int:
        return max(0, self.quantity - (self.quantity_received or 0))

    @property
    def cost(self) -> float:
        return (self.unit_price or 0.0) * self.quantity


# --- serialized spares (inventory step 4) --------------------------------------------------

UNIT_STATES = ("in_stock", "in_machine", "at_repair", "retired")
UNIT_STATE_LABELS = {"in_stock": "In stock", "in_machine": "In a machine",
                     "at_repair": "Out for repair", "retired": "Retired"}


class SerialUnit(db.Model):
    """One unit of a part tracked one by one (a board, a monitor, a coin mech): where it is
    now. Exactly one of place (in stock), machine (installed), or repair (out) is set while
    it is in service. Its label (/u/<code>) never changes."""

    __tablename__ = "serial_unit"
    __table_args__ = (db.UniqueConstraint("item_id", "serial", name="uq_serial_unit_item_serial"),)

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_item.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    serial = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(16), nullable=False, unique=True,
                     default=lambda: _new_code())
    state = db.Column(db.String(20), nullable=False, default="in_stock")
    place_id = db.Column(db.Integer, db.ForeignKey("stock_place.id"), nullable=True,
                         index=True)
    game_id = db.Column(db.Integer, db.ForeignKey("game.id", ondelete="SET NULL",
                                                  name="fk_serial_unit_game_id"),
                        nullable=True, index=True)
    repair_with = db.Column(db.String(200), nullable=True)     # who has it, when out
    notes = db.Column(db.Text, nullable=True)
    created = db.Column(db.DateTime, nullable=False, default=_now)

    item = db.relationship("InventoryItem",
                           backref=db.backref("units", cascade="all, delete-orphan",
                                              order_by="SerialUnit.serial"))
    place = db.relationship("StockPlace")
    game = db.relationship("Game", backref="serial_units")
    events = db.relationship("UnitEvent", backref="unit", cascade="all, delete-orphan",
                             order_by="UnitEvent.id.desc()")

    @property
    def where(self) -> str:
        if self.state == "in_stock" and self.place is not None:
            return self.place.path
        if self.state == "in_machine" and self.game is not None:
            return self.game.name
        if self.state == "at_repair":
            return f"Out for repair{' with ' + self.repair_with if self.repair_with else ''}"
        return UNIT_STATE_LABELS.get(self.state, self.state)


class UnitEvent(db.Model):
    """One thing that happened to a unit. Only ever added to."""

    __tablename__ = "unit_event"

    id = db.Column(db.Integer, primary_key=True)
    unit_id = db.Column(db.Integer, db.ForeignKey("serial_unit.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    kind = db.Column(db.String(20), nullable=False)
    detail = db.Column(db.String(300), nullable=True)      # "Shelf A → Neon Raider"
    note = db.Column(db.String(500), nullable=True)
    order_id = db.Column(db.Integer, db.ForeignKey("maintenance_record.id",
                                                   ondelete="SET NULL",
                                                   name="fk_unit_event_order_id"),
                         nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL",
                                                  name="fk_unit_event_user_id"),
                        nullable=True, index=True)
    at = db.Column(db.DateTime, nullable=False, default=_now)

    user = db.relationship("User")
    order = db.relationship("MaintenanceRecord")


def _new_code() -> str:
    from app.models.stock import new_code

    return new_code()


# --- counts (inventory step 5) --------------------------------------------------------------

COUNT_STATUSES = ("Counting", "Applied", "Cancelled")


class StockCount(db.Model):
    """A planned count: a full count of some places, or a cycle count of the parts counted
    longest ago. Counters fill its lines blind (they don't see what's on record); nothing
    changes until a manager reviews the differences and applies them. A count can repeat."""

    __tablename__ = "stock_count"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    kind = db.Column(db.String(10), nullable=False, default="full")     # full | cycle
    status = db.Column(db.String(20), nullable=False, default="Counting")
    due = db.Column(db.Date, nullable=True)
    repeat_days = db.Column(db.Integer, nullable=True)
    cycle_size = db.Column(db.Integer, nullable=True)
    # A full count's places, as ids ("3,7"): kept so a repeat counts the same places.
    place_ids = db.Column(db.String(500), nullable=True)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL",
                                                        name="fk_stock_count_created_by_id"),
                              nullable=True, index=True)
    created = db.Column(db.DateTime, nullable=False, default=_now)
    applied = db.Column(db.DateTime, nullable=True)
    applied_by_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL",
                                                        name="fk_stock_count_applied_by_id"),
                              nullable=True, index=True)

    created_by = db.relationship("User", foreign_keys=[created_by_id])
    applied_by = db.relationship("User", foreign_keys=[applied_by_id])
    lines = db.relationship("StockCountLine", backref="count", cascade="all, delete-orphan",
                            order_by="StockCountLine.id")

    @property
    def counted(self) -> int:
        return sum(1 for line in self.lines if line.counted is not None)


class StockCountLine(db.Model):
    """One part in one place on a count: what was on record when it started, and what was
    counted."""

    __tablename__ = "stock_count_line"
    __table_args__ = (db.UniqueConstraint("count_id", "item_id", "place_id",
                                          name="uq_stock_count_line"),)

    id = db.Column(db.Integer, primary_key=True)
    count_id = db.Column(db.Integer, db.ForeignKey("stock_count.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_item.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    place_id = db.Column(db.Integer, db.ForeignKey("stock_place.id"), nullable=False,
                         index=True)
    expected = db.Column(db.Integer, nullable=False, default=0)
    counted = db.Column(db.Integer, nullable=True)
    counted_by_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL",
                                                        name="fk_stock_count_line_counted_by_id"),
                              nullable=True, index=True)
    counted_at = db.Column(db.DateTime, nullable=True)

    item = db.relationship("InventoryItem")
    place = db.relationship("StockPlace")
    counted_by = db.relationship("User")
