"""Where stock is: places (a free tree) and how many of each part are in each one.

``InventoryItem.stock_quantity`` stays, as the total over every place, so the lists, reports
and low-stock checks that read it keep working. ``app.services.stock`` is the only code that
changes a level, and it keeps that total in step.

Places nest as deep as the building needs ("Warehouse › Shelf A › Bin 3"); a cart or van is
just another top-level place. Stock that was here before places existed starts in
"Unsorted", which cannot be archived or renamed away.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

from app.extensions import db

# Label codes: short enough to type, no look-alikes (0/o, 1/l/i). Printed labels encode
# /p/<code> and /i/<code>, so a code never changes once made.
CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
CODE_LENGTH = 6
UNSORTED_CODE = "unsorted"
MAX_DEPTH = 6


def new_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class StockPlace(db.Model):
    """A room, shelf, drawer, bin, cart or van that holds parts."""

    __tablename__ = "stock_place"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey("stock_place.id"), nullable=True,
                          index=True)
    code = db.Column(db.String(16), nullable=False, unique=True, default=new_code)
    notes = db.Column(db.Text, nullable=True)
    archived = db.Column(db.Boolean, nullable=False, default=False)
    created = db.Column(db.DateTime, nullable=False, default=_now)

    parent = db.relationship("StockPlace", remote_side=[id], backref="children")

    @property
    def is_unsorted(self) -> bool:
        return self.code == UNSORTED_CODE

    def lineage(self) -> list[StockPlace]:
        """This place and its ancestors, outermost first."""
        chain, place = [], self
        while place is not None and len(chain) <= MAX_DEPTH + 1:
            chain.append(place)
            place = place.parent
        return chain[::-1]

    @property
    def path(self) -> str:
        return " › ".join(p.name for p in self.lineage())

    def descendants(self) -> list[StockPlace]:
        out, todo = [], list(self.children)
        while todo:
            place = todo.pop(0)
            out.append(place)
            todo.extend(place.children)
        return out

    def __repr__(self) -> str:
        return f"<StockPlace {self.path!r}>"


class StockLevel(db.Model):
    """How many of one part are in one place. A row at zero is kept until the part moves on,
    so a counted-empty bin still shows the part belongs there."""

    __tablename__ = "stock_level"
    __table_args__ = (db.UniqueConstraint("item_id", "place_id", name="uq_stock_level_item_place"),)

    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("inventory_item.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    place_id = db.Column(db.Integer, db.ForeignKey("stock_place.id"), nullable=False,
                         index=True)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    counted = db.Column(db.DateTime, nullable=True)   # when it was last counted, not changed

    item = db.relationship("InventoryItem",
                           backref=db.backref("levels", cascade="all, delete-orphan"))
    place = db.relationship("StockPlace", backref="levels")

    def __repr__(self) -> str:
        return f"<StockLevel item={self.item_id} place={self.place_id} qty={self.quantity}>"
