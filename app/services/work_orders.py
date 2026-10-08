"""Work orders: listing, parts, photos.

The parts logic was copied three times in the maintenance blueprint (machine order, general
order, update; F-3). It lives here once, and the routes only parse the request and report.
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field

from sqlalchemy.orm import joinedload, selectinload

from app.extensions import db
from app.models import (
    Game,
    InventoryItem,
    InventoryRequest,
    InventoryRequestHistory,
    MaintenanceInventoryUsage,
    MaintenanceRecord,
    StockHistory,
    WorkLog,
)
from app.services.stock import check_low_stock_alert

OPEN_STATUSES = ("Open", "In_Progress")
CLOSED_STATUSES = ("Fixed", "Deferred")
STATUSES = OPEN_STATUSES + CLOSED_STATUSES
PRIORITIES = ("Low", "Medium", "High", "Critical")
URGENCIES = ("Low", "Normal", "High", "Urgent")
SOURCES = {"gatbox": "GATBOX at the bench", "coindoor": "the coin door", "web": "this app"}
PRIORITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

MAX_PHOTOS_PER_RECORD = 10
MAX_TOTAL_STORAGE_MB = 500
MAX_PART_ROWS = 10


# --- listing -------------------------------------------------------------------------------

@dataclass
class OrderList:
    orders: list[MaintenanceRecord]
    counts: dict[str, int]
    tab: str
    sort: str
    search: str


TABS = ("open", "closed", "all")
SORTS = {"priority": "Priority", "newest": "Newest first", "oldest": "Oldest first",
         "machine": "Machine"}


def list_orders(tab: str = "open", search: str = "", sort: str = "") -> OrderList:
    tab = tab if tab in TABS else "open"
    sort = sort if sort in SORTS else ("priority" if tab == "open" else "newest")

    query = MaintenanceRecord.query.options(joinedload(MaintenanceRecord.game))
    if search:
        like = f"%{search}%"
        query = query.outerjoin(Game).filter(
            MaintenanceRecord.issue_description.ilike(like)
            | MaintenanceRecord.technician.ilike(like)
            | MaintenanceRecord.work_order_type.ilike(like)
            | MaintenanceRecord.location_description.ilike(like)
            | Game.name.ilike(like)
        )
    everything = query.all()
    counts = {
        "open": sum(o.status in OPEN_STATUSES for o in everything),
        "closed": sum(o.status not in OPEN_STATUSES for o in everything),
        "all": len(everything),
    }
    if tab == "open":
        orders = [o for o in everything if o.status in OPEN_STATUSES]
    elif tab == "closed":
        orders = [o for o in everything if o.status not in OPEN_STATUSES]
    else:
        orders = everything

    def when(o):
        return o.date_reported.timestamp() if o.date_reported else 0.0

    if sort == "priority":
        orders.sort(key=lambda o: (PRIORITY_RANK.get(o.priority, 9), -when(o)))
    elif sort == "newest":
        orders.sort(key=lambda o: -when(o))
    elif sort == "oldest":
        orders.sort(key=when)
    else:
        orders.sort(key=lambda o: ((o.game.name.lower() if o.game else "~"), -when(o)))
    return OrderList(orders=orders, counts=counts, tab=tab, sort=sort, search=search)


def load_order(record_id: int) -> MaintenanceRecord | None:
    """One order with everything its page shows, loaded up front (no query per log line)."""
    return (
        MaintenanceRecord.query.options(
            joinedload(MaintenanceRecord.game),
            selectinload(MaintenanceRecord.work_logs).joinedload(WorkLog.user),
            selectinload(MaintenanceRecord.inventory_usage).joinedload(
                MaintenanceInventoryUsage.item),
            selectinload(MaintenanceRecord.inventory_requests).joinedload(
                InventoryRequest.requested_by),
        )
        .filter_by(id=record_id)
        .first()
    )


# --- parts ---------------------------------------------------------------------------------

@dataclass
class PartsResult:
    cost: float = 0.0
    used: int = 0
    requested: int = 0
    warnings: list[str] = field(default_factory=list)


def use_parts(record: MaintenanceRecord, rows: list[tuple[int, int]], user_id: int,
              reason: str) -> PartsResult:
    """Take parts out of stock for *record*. Rows short on stock are skipped with a warning.

    Adds the parts' cost to the record's cost. Stages everything; the caller commits.
    """
    result = PartsResult()
    for item_id, quantity in rows:
        item = db.session.get(InventoryItem, item_id)
        if item is None or quantity <= 0:
            continue
        if item.stock_quantity < quantity:
            result.warnings.append(f"Insufficient stock for {item.name}. "
                                   f"Available: {item.stock_quantity}, Requested: {quantity}")
            continue
        usage = MaintenanceInventoryUsage(
            maintenance_id=record.id, item_id=item.id, quantity_used=quantity,
            unit_price_at_time=item.unit_price, total_cost=quantity * item.unit_price)
        db.session.add(usage)
        before = item.stock_quantity
        item.stock_quantity -= quantity
        db.session.add(StockHistory(
            item_id=item.id, change_type="used", quantity_change=-quantity,
            previous_quantity=before, new_quantity=item.stock_quantity,
            reason=reason, user_id=user_id))
        check_low_stock_alert(item)
        result.cost += usage.total_cost
        result.used += 1
    if result.cost:
        record.cost = (record.cost or 0) + result.cost
    return result


def request_parts(record: MaintenanceRecord, rows: list[tuple[int, int, str]],
                  user_id: int) -> int:
    """Raise an inventory request for each (item, quantity, urgency) row, linked to *record*."""
    made = 0
    for item_id, quantity, urgency in rows:
        item = db.session.get(InventoryItem, item_id)
        if quantity <= 0:
            continue
        req = InventoryRequest(
            item_id=item_id, maintenance_id=record.id,
            item_name=item.name if item else "Unknown Item",
            quantity_requested=quantity,
            reason=f"Needed for Work Order #{record.id}: {record.issue_description[:100]}",
            urgency=urgency if urgency in URGENCIES else "Normal",
            status="Pending", requested_by_id=user_id)
        db.session.add(req)
        db.session.flush()
        db.session.add(InventoryRequestHistory(
            request_id=req.id, user_id=user_id, action="created",
            notes="Request created from work order update"))
        made += 1
    return made


# --- photos --------------------------------------------------------------------------------

def photo_dir(static_folder: str) -> str:
    return os.path.join(static_folder, "maintenance_photos")


def save_photos(record: MaintenanceRecord, files, static_folder: str,
                on_saved=None) -> tuple[int, list[str]]:
    """Save uploaded photos for *record*: re-encoded to JPEG, at most 10 per order.

    Returns (saved, problems). A file Pillow cannot read is refused and nothing is attached
    (F-8: it used to be attached anyway, as a broken photo). Files are named .jpg, because
    that is what they are. ``on_saved(path, name)`` runs after each save (the S3 copy).
    """
    from app.utils.helpers import allowed_file, compress_and_save_image, get_directory_size

    folder = photo_dir(static_folder)
    os.makedirs(folder, exist_ok=True)
    problems: list[str] = []
    if get_directory_size(folder) > MAX_TOTAL_STORAGE_MB:
        return 0, [f"Photo storage is full ({MAX_TOTAL_STORAGE_MB} MB). Ask an admin to clean up."]

    saved = 0
    for upload in files:
        if not upload or not upload.filename:
            continue
        if not allowed_file(upload.filename):
            problems.append(f"{upload.filename}: not a photo (PNG, JPG or GIF).")
            continue
        if len(record.get_photos()) >= MAX_PHOTOS_PER_RECORD:
            problems.append(f"An order holds at most {MAX_PHOTOS_PER_RECORD} photos.")
            break
        name = f"maintenance_{record.id}_{uuid.uuid4().hex[:8]}.jpg"
        path = os.path.join(folder, name)
        if not compress_and_save_image(upload, path):
            if os.path.exists(path):
                os.remove(path)
            problems.append(f"{upload.filename}: could not be read as an image.")
            continue
        record.add_photo(name)
        if on_saved:
            on_saved(path, name)
        saved += 1
    return saved, problems


def delete_photo(record: MaintenanceRecord, filename: str, static_folder: str) -> bool:
    """Remove one of *record*'s photos. Refuses any name the order does not hold (F-18: the
    route used to delete whatever filename it was given from the photo folder)."""
    if filename not in record.get_photos():
        return False
    record.remove_photo(filename)
    path = os.path.join(photo_dir(static_folder), filename)
    if os.path.isfile(path):
        os.remove(path)
    return True
