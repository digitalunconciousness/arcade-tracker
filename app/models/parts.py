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
