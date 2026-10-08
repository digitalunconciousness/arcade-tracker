"""Stock levels and low-stock alerts."""
from __future__ import annotations

import datetime as dt
from datetime import datetime

from app.extensions import db
from app.models import InventoryItem, LowStockAlert


def check_low_stock_alert(item: InventoryItem) -> None:
    """Open an alert when *item* is at or below its minimum, resolve open ones when not.

    Was copied in the maintenance and inventory blueprints (F-3), and committed in the middle
    of its caller's work. It now only stages the change: the caller commits once.
    """
    open_alerts = LowStockAlert.query.filter_by(item_id=item.id, resolved=False).all()
    if item.is_low_stock():
        if not open_alerts:
            db.session.add(LowStockAlert(item_id=item.id, email_sent=False))
    else:
        for alert in open_alerts:
            alert.resolved = True
            alert.resolved_date = datetime.now(dt.UTC)
