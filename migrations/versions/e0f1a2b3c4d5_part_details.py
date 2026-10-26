"""Part details (inventory step 2): categories, units and packs, photos, suppliers, prices.

Adds ``part_category``, ``supplier``, ``item_supplier`` and ``price_change``, and on
``inventory_item`` a ``category_id``, ``unit`` (default "each"), ``pack_size`` and
``photo_filename``.

Data: the starting categories are added once. Each part's free-text ``supplier`` becomes a
``supplier`` row (spellings that differ only in case or spacing are one supplier, named as
first seen) and that part's preferred supplier, priced at the part's unit price when it has
one. ``inventory_item.supplier`` is left as it is. Guarded like its neighbours, so a re-run
is harmless.

Revision ID: e0f1a2b3c4d5
Revises: d9e0f1a2b3c4
"""

import sqlalchemy as sa
from alembic import op

revision = "e0f1a2b3c4d5"
down_revision = "d9e0f1a2b3c4"
branch_labels = None
depends_on = None

# Copied, not imported: a migration must not change when the app's code does.
DEFAULT_CATEGORIES = (
    "Switches & buttons", "Coin & token mechs", "Lamps & LEDs", "Fuses & electrical",
    "Boards & power supplies", "Joysticks & controls", "Belts & mechanical",
    "Cleaning & consumables", "Tickets & prizes",
)
ITEM_COLUMNS = ("category_id", "unit", "pack_size", "photo_filename")


def _inspector():
    return sa.inspect(op.get_bind())


def _columns(table):
    return {c["name"] for c in _inspector().get_columns(table)}


def upgrade():
    bind = op.get_bind()
    if not _inspector().has_table("part_category"):
        op.create_table(
            "part_category",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(60), nullable=False, unique=True),
        )
    if not _inspector().has_table("supplier"):
        op.create_table(
            "supplier",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(200), nullable=False, unique=True),
            sa.Column("website", sa.String(300), nullable=True),
            sa.Column("phone", sa.String(50), nullable=True),
            sa.Column("account_number", sa.String(100), nullable=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
        )
    if not _inspector().has_table("item_supplier"):
        op.create_table(
            "item_supplier",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("item_id", sa.Integer(),
                      sa.ForeignKey("inventory_item.id", ondelete="CASCADE"), nullable=False),
            sa.Column("supplier_id", sa.Integer(), sa.ForeignKey("supplier.id"),
                      nullable=False),
            sa.Column("supplier_part_number", sa.String(100), nullable=True),
            sa.Column("price", sa.Float(), nullable=True),
            sa.Column("pack_size", sa.Integer(), nullable=True),
            sa.Column("url", sa.String(500), nullable=True),
            sa.Column("preferred", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.UniqueConstraint("item_id", "supplier_id",
                                name="uq_item_supplier_item_supplier"),
        )
        op.create_index("ix_item_supplier_item_id", "item_supplier", ["item_id"])
        op.create_index("ix_item_supplier_supplier_id", "item_supplier", ["supplier_id"])
    if not _inspector().has_table("price_change"):
        op.create_table(
            "price_change",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("item_id", sa.Integer(),
                      sa.ForeignKey("inventory_item.id", ondelete="CASCADE"), nullable=False),
            sa.Column("supplier_id", sa.Integer(),
                      sa.ForeignKey("supplier.id", ondelete="SET NULL",
                                    name="fk_price_change_supplier_id"), nullable=True),
            sa.Column("old_price", sa.Float(), nullable=True),
            sa.Column("new_price", sa.Float(), nullable=True),
            sa.Column("reason", sa.String(200), nullable=True),
            sa.Column("user_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL",
                                    name="fk_price_change_user_id"), nullable=True),
            sa.Column("changed", sa.DateTime(), nullable=False),
        )
        for column in ("item_id", "supplier_id", "user_id"):
            op.create_index(f"ix_price_change_{column}", "price_change", [column])

    have = _columns("inventory_item")
    with op.batch_alter_table("inventory_item") as batch:
        if "category_id" not in have:
            batch.add_column(sa.Column("category_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_inventory_item_category_id", "part_category",
                                     ["category_id"], ["id"], ondelete="SET NULL")
        if "unit" not in have:
            batch.add_column(sa.Column("unit", sa.String(20), nullable=False,
                                       server_default="each"))
        if "pack_size" not in have:
            batch.add_column(sa.Column("pack_size", sa.Integer(), nullable=True))
        if "photo_filename" not in have:
            batch.add_column(sa.Column("photo_filename", sa.String(255), nullable=True))
    if "ix_inventory_item_category_id" not in {
            i["name"] for i in _inspector().get_indexes("inventory_item")}:
        op.create_index("ix_inventory_item_category_id", "inventory_item", ["category_id"])

    # --- data ---------------------------------------------------------------------------
    categories = sa.table("part_category", sa.column("name", sa.String))
    if bind.execute(sa.select(sa.func.count()).select_from(categories)).scalar() == 0:
        bind.execute(categories.insert(), [{"name": n} for n in DEFAULT_CATEGORIES])

    items = sa.table("inventory_item", sa.column("id", sa.Integer),
                     sa.column("supplier", sa.String), sa.column("unit_price", sa.Float))
    suppliers = sa.table("supplier", sa.column("id", sa.Integer), sa.column("name", sa.String),
                         sa.column("archived", sa.Boolean))
    links = sa.table("item_supplier", sa.column("item_id", sa.Integer),
                     sa.column("supplier_id", sa.Integer), sa.column("price", sa.Float),
                     sa.column("preferred", sa.Boolean))
    by_key = {" ".join(r.name.split()).lower(): r.id
              for r in bind.execute(sa.select(suppliers.c.id, suppliers.c.name))}
    linked = {r.item_id for r in bind.execute(sa.select(links.c.item_id))}
    rows = bind.execute(sa.select(items.c.id, items.c.supplier, items.c.unit_price)
                        .order_by(items.c.id)).all()
    for row in rows:
        name = " ".join((row.supplier or "").split())
        if not name or row.id in linked:
            continue
        key = name.lower()
        if key not in by_key:
            bind.execute(suppliers.insert().values(name=name[:200], archived=False))
            by_key[key] = bind.execute(sa.select(suppliers.c.id)
                                       .where(suppliers.c.name == name[:200])).scalar()
        price = row.unit_price if row.unit_price and row.unit_price > 0 else None
        bind.execute(links.insert().values(item_id=row.id, supplier_id=by_key[key],
                                           price=price, preferred=True))


def downgrade():
    if "ix_inventory_item_category_id" in {
            i["name"] for i in _inspector().get_indexes("inventory_item")}:
        op.drop_index("ix_inventory_item_category_id", table_name="inventory_item")
    have = _columns("inventory_item")
    with op.batch_alter_table("inventory_item") as batch:
        if "category_id" in have:
            batch.drop_constraint("fk_inventory_item_category_id", type_="foreignkey")
        for column in ITEM_COLUMNS:
            if column in have:
                batch.drop_column(column)
    for table in ("price_change", "item_supplier", "supplier", "part_category"):
        if _inspector().has_table(table):
            op.drop_table(table)
