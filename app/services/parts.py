"""Part details (inventory step 2): categories, units, suppliers and the price log.

``InventoryItem.supplier`` (the old free-text field) is kept as a copy of the preferred
supplier's name, so the parts list, its search and the low-stock page read it as before.
Every price change, the part's own or a supplier's, goes through here and is logged.
Callers commit.
"""

from __future__ import annotations

import re

from app.extensions import db
from app.models import InventoryItem, ItemSupplier, PartCategory, PriceChange, Supplier
from app.models.parts import UNITS


class PartError(ValueError):
    """A change that can't be made; the message is for the person who asked."""


def clean(text: str | None, limit: int, what: str, required: bool = False) -> str | None:
    text = " ".join((text or "").split())
    if not text:
        if required:
            raise PartError(f"Give the {what}.")
        return None
    if len(text) > limit:
        raise PartError(f"Keep the {what} to {limit} characters.")
    return text


def clean_unit(text: str | None) -> str:
    unit = clean(text, 20, "unit") or "each"
    return unit.lower() if unit.lower() in UNITS else unit


def clean_pack(value) -> int | None:
    """A pack size: blank or 1 is "sold singly"."""
    if value in (None, ""):
        return None
    try:
        size = int(value)
    except (TypeError, ValueError):
        raise PartError("A pack size is a whole number.") from None
    if size < 1 or size > 100_000:
        raise PartError("A pack size is between 1 and 100,000.")
    return None if size == 1 else size


def clean_price(value) -> float | None:
    if value in (None, ""):
        return None
    try:
        price = round(float(str(value).replace("$", "").replace(",", "").strip()), 4)
    except ValueError:
        raise PartError("A price is a number, like 4.50.") from None
    if price < 0 or price > 1_000_000:
        raise PartError("A price is between 0 and 1,000,000.")
    return price


def clean_url(text: str | None) -> str | None:
    """A web address: http(s) only, with https:// added when it was left off."""
    url = clean(text, 500, "link")
    if not url or url.lower().startswith(("https://", "http://")):
        return url
    if re.match(r"^[a-z][a-z0-9+.-]*:(?!\d)", url, re.IGNORECASE):
        raise PartError("A link is a web address, starting https://")
    return "https://" + url


# --- prices -------------------------------------------------------------------------------

def _log(item, old, new, user_id, reason, supplier=None):
    if (old or None) == (new or None) or (old is not None and new is not None
                                          and abs(old - new) < 0.00005):
        return
    db.session.add(PriceChange(item=item, supplier=supplier, old_price=old, new_price=new,
                               user_id=user_id, reason=(reason or "")[:200] or None))


def set_item_price(item: InventoryItem, price: float | None, user_id: int | None,
                   reason: str = "Edited") -> None:
    """The part's own unit price: what a work order is charged for one."""
    old = item.unit_price if item.id is not None else None
    item.unit_price = price or 0.0
    if item.id is not None:
        _log(item, old or None, price, user_id, reason)


def first_price(item: InventoryItem, user_id: int | None) -> None:
    """Log a new part's starting price (called once it has an id)."""
    if item.unit_price:
        _log(item, None, item.unit_price, user_id, "Starting price")


# --- categories ---------------------------------------------------------------------------

def categories() -> list[PartCategory]:
    return PartCategory.query.order_by(db.func.lower(PartCategory.name)).all()


def save_category(name: str | None, category: PartCategory | None = None) -> PartCategory:
    name = clean(name, 60, "category's name", required=True)
    clash = PartCategory.query.filter(db.func.lower(PartCategory.name) == name.lower()).first()
    if clash is not None and clash is not category:
        raise PartError(f"There is already a category called {clash.name}.")
    if category is None:
        category = PartCategory(name=name)
        db.session.add(category)
    else:
        category.name = name
    return category


def delete_category(category: PartCategory) -> int:
    """Delete a category; its parts keep everything else and become uncategorised."""
    count = len(category.items)
    for item in category.items:
        item.category = None
    db.session.delete(category)
    return count


# --- suppliers ----------------------------------------------------------------------------

def find_supplier(name: str | None) -> Supplier | None:
    name = " ".join((name or "").split())
    if not name:
        return None
    return Supplier.query.filter(db.func.lower(Supplier.name) == name.lower()).first()


def supplier_for(name: str | None) -> Supplier | None:
    """The supplier called *name* (any case), made if there isn't one; None for a blank."""
    name = clean(name, 200, "supplier's name")
    if name is None:
        return None
    supplier = find_supplier(name)
    if supplier is None:
        supplier = Supplier(name=name)
        db.session.add(supplier)
        db.session.flush()
    elif supplier.archived:
        supplier.archived = False
    return supplier


def save_supplier(supplier: Supplier | None, form) -> Supplier:
    name = clean(form.get("name"), 200, "supplier's name", required=True)
    clash = find_supplier(name)
    if clash is not None and clash is not supplier:
        raise PartError(f"There is already a supplier called {clash.name}.")
    if supplier is None:
        supplier = Supplier(name=name)
        db.session.add(supplier)
    supplier.name = name
    supplier.website = clean_url(form.get("website"))
    supplier.phone = clean(form.get("phone"), 50, "phone number")
    supplier.account_number = clean(form.get("account_number"), 100, "account number")
    supplier.notes = clean(form.get("notes"), 2000, "notes")
    db.session.flush()
    for link in supplier.parts:
        if link.preferred:
            link.item.supplier = supplier.name
    return supplier


def _same(link: ItemSupplier, supplier: Supplier) -> bool:
    # A link made in this request has no supplier_id until the session flushes.
    return link.supplier is supplier or (supplier.id is not None
                                         and link.supplier_id == supplier.id)


def link_for(item: InventoryItem, supplier: Supplier) -> ItemSupplier:
    for link in item.suppliers:
        if _same(link, supplier):
            return link
    link = ItemSupplier(item=item, supplier=supplier, preferred=False)
    db.session.add(link)
    return link


def set_preferred(item: InventoryItem, supplier: Supplier | None) -> None:
    """Make *supplier* the part's preferred one (None: no preferred supplier). Keeps the old
    ``supplier`` text in step."""
    for link in item.suppliers:
        link.preferred = supplier is not None and _same(link, supplier)
    if supplier is not None:
        link_for(item, supplier).preferred = True
    item.supplier = supplier.name if supplier is not None else None


def preferred(item: InventoryItem) -> ItemSupplier | None:
    return next((link for link in item.suppliers if link.preferred), None)


def save_link(item: InventoryItem, form, user_id: int | None,
              link: ItemSupplier | None = None) -> ItemSupplier:
    """Add a supplier to a part, or change one: their part number, price, pack and link."""
    if link is None:
        supplier = supplier_for(form.get("supplier"))
        if supplier is None:
            raise PartError("Give the supplier's name.")
        if any(_same(lk, supplier) for lk in item.suppliers):
            raise PartError(f"{supplier.name} is already listed for this part.")
        link = link_for(item, supplier)
    old_price = link.price
    link.supplier_part_number = clean(form.get("supplier_part_number"), 100, "part number")
    link.price = clean_price(form.get("price"))
    link.pack_size = clean_pack(form.get("pack_size"))
    link.url = clean_url(form.get("url"))
    _log(item, old_price, link.price, user_id, "Supplier price", link.supplier)
    if form.get("preferred") == "1" or preferred(item) is None:
        set_preferred(item, link.supplier)
    return link


def remove_link(link: ItemSupplier) -> None:
    item, was_preferred = link.item, link.preferred
    item.suppliers.remove(link)
    db.session.delete(link)
    if was_preferred:
        nxt = item.suppliers[0].supplier if item.suppliers else None
        set_preferred(item, nxt)
