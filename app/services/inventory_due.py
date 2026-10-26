"""What inventory needs from people today (inventory step 6): counts due, deliveries due,
and parts to buy. Shared by the dashboard and the daily alert summary."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from app.models import InventoryRequest, PurchaseOrder, StockCount
from app.models.parts import PO_OPEN
from app.services.collection import local_today


@dataclass
class InventoryDue:
    counts: list[StockCount] = field(default_factory=list)          # open, oldest due first
    counts_late: int = 0                                             # of those, overdue
    orders_due: list[PurchaseOrder] = field(default_factory=list)   # expected by today
    requests_due: list[InventoryRequest] = field(default_factory=list)
    to_buy: int = 0                                                  # shopping list rows

    @property
    def deliveries(self) -> int:
        return len(self.orders_due) + len(self.requests_due)

    @property
    def anything(self) -> bool:
        return bool(self.counts or self.deliveries or self.to_buy)


def due(today: dt.date | None = None, shopping: bool = False) -> InventoryDue:
    """*shopping* also counts the shopping list (managers only; it reads every part)."""
    today = today or local_today()
    counts = (StockCount.query.filter_by(status="Counting")
              .order_by(StockCount.due.is_(None), StockCount.due, StockCount.id).all())
    out = InventoryDue(
        counts=counts,
        counts_late=sum(1 for c in counts if c.due and c.due < today),
        orders_due=(PurchaseOrder.query.filter(PurchaseOrder.status.in_(PO_OPEN[1:]),
                                               PurchaseOrder.expected.isnot(None),
                                               PurchaseOrder.expected <= today)
                    .order_by(PurchaseOrder.expected).all()),
        requests_due=(InventoryRequest.query.filter(
            InventoryRequest.status.in_(("Ordered", "Shipped")),
            InventoryRequest.estimated_arrival.isnot(None),
            InventoryRequest.estimated_arrival <= today)
            .order_by(InventoryRequest.estimated_arrival).all()),
    )
    if shopping:
        from app.services.purchasing import shopping_list

        out.to_buy = sum(len(g.rows) for g in shopping_list())
    return out
