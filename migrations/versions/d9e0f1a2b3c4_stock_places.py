"""Stock places: where parts are (inventory step 1).

Adds ``stock_place`` (a free tree of rooms, shelves, bins, carts) and ``stock_level`` (how
many of each part in each place), a label ``code`` on ``inventory_item``, and
``place_id``/``to_place_id`` on ``stock_history``.

Existing stock is not lost or guessed at: one top-level place, "Unsorted", is made, and each
part's current ``stock_quantity`` becomes its level there. Totals are unchanged. Every
existing part gets a label code. Guarded like its neighbours, so a re-run is harmless.

Revision ID: d9e0f1a2b3c4
Revises: c8d9e0f1a2b3
"""

import secrets
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "d9e0f1a2b3c4"
down_revision = "c8d9e0f1a2b3"
branch_labels = None
depends_on = None

# Copied, not imported: a migration must not change when the app's code does.
CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
UNSORTED_CODE = "unsorted"


def _code(taken):
    while True:
        code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(6))
        if code not in taken:
            taken.add(code)
            return code


def _inspector():
    return sa.inspect(op.get_bind())


def _columns(table):
    return {c["name"] for c in _inspector().get_columns(table)}


def upgrade():
    bind = op.get_bind()
    if not _inspector().has_table("stock_place"):
        op.create_table(
            "stock_place",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(100), nullable=False),
            sa.Column("parent_id", sa.Integer(), sa.ForeignKey("stock_place.id"),
                      nullable=True),
            sa.Column("code", sa.String(16), nullable=False, unique=True),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("created", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_stock_place_parent_id", "stock_place", ["parent_id"])
    if not _inspector().has_table("stock_level"):
        op.create_table(
            "stock_level",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("item_id", sa.Integer(),
                      sa.ForeignKey("inventory_item.id", ondelete="CASCADE"), nullable=False),
            sa.Column("place_id", sa.Integer(), sa.ForeignKey("stock_place.id"),
                      nullable=False),
            sa.Column("quantity", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("counted", sa.DateTime(), nullable=True),
            sa.UniqueConstraint("item_id", "place_id", name="uq_stock_level_item_place"),
        )
        op.create_index("ix_stock_level_item_id", "stock_level", ["item_id"])
        op.create_index("ix_stock_level_place_id", "stock_level", ["place_id"])
    if "code" not in _columns("inventory_item"):
        op.add_column("inventory_item", sa.Column("code", sa.String(16), nullable=True))
        op.create_index("ix_inventory_item_code", "inventory_item", ["code"], unique=True)
    history = _columns("stock_history")
    with op.batch_alter_table("stock_history") as batch:
        if "place_id" not in history:
            batch.add_column(sa.Column("place_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_stock_history_place_id", "stock_place",
                                     ["place_id"], ["id"], ondelete="SET NULL")
        if "to_place_id" not in history:
            batch.add_column(sa.Column("to_place_id", sa.Integer(), nullable=True))
            batch.create_foreign_key("fk_stock_history_to_place_id", "stock_place",
                                     ["to_place_id"], ["id"], ondelete="SET NULL")
    indexes = {i["name"] for i in _inspector().get_indexes("stock_history")}
    for column in ("place_id", "to_place_id"):
        if f"ix_stock_history_{column}" not in indexes:
            op.create_index(f"ix_stock_history_{column}", "stock_history", [column])

    # --- data: label codes, and today's stock into "Unsorted" ----------------------------
    items = sa.table("inventory_item", sa.column("id", sa.Integer),
                     sa.column("code", sa.String), sa.column("stock_quantity", sa.Integer))
    places = sa.table("stock_place", sa.column("id", sa.Integer), sa.column("name", sa.String),
                      sa.column("code", sa.String), sa.column("archived", sa.Boolean),
                      sa.column("created", sa.DateTime))
    levels = sa.table("stock_level", sa.column("item_id", sa.Integer),
                      sa.column("place_id", sa.Integer), sa.column("quantity", sa.Integer))

    taken = {r.code for r in bind.execute(sa.select(items.c.code)) if r.code}
    taken |= {r.code for r in bind.execute(sa.select(places.c.code))}
    for row in bind.execute(sa.select(items.c.id).where(items.c.code.is_(None))).all():
        bind.execute(items.update().where(items.c.id == row.id).values(code=_code(taken)))

    unsorted = bind.execute(sa.select(places.c.id)
                            .where(places.c.code == UNSORTED_CODE)).scalar()
    if unsorted is None:
        bind.execute(places.insert().values(
            name="Unsorted", code=UNSORTED_CODE, archived=False,
            created=datetime.now(UTC).replace(tzinfo=None)))
        unsorted = bind.execute(sa.select(places.c.id)
                                .where(places.c.code == UNSORTED_CODE)).scalar()
    placed = {r.item_id for r in bind.execute(sa.select(levels.c.item_id))}
    for row in bind.execute(sa.select(items.c.id, items.c.stock_quantity)).all():
        if row.id not in placed and (row.stock_quantity or 0) > 0:
            bind.execute(levels.insert().values(item_id=row.id, place_id=unsorted,
                                                quantity=row.stock_quantity))


def downgrade():
    indexes = {i["name"] for i in _inspector().get_indexes("stock_history")}
    for column in ("place_id", "to_place_id"):
        if f"ix_stock_history_{column}" in indexes:
            op.drop_index(f"ix_stock_history_{column}", table_name="stock_history")
    history = _columns("stock_history")
    with op.batch_alter_table("stock_history") as batch:
        if "to_place_id" in history:
            batch.drop_constraint("fk_stock_history_to_place_id", type_="foreignkey")
            batch.drop_column("to_place_id")
        if "place_id" in history:
            batch.drop_constraint("fk_stock_history_place_id", type_="foreignkey")
            batch.drop_column("place_id")
    if "code" in _columns("inventory_item"):
        op.drop_index("ix_inventory_item_code", table_name="inventory_item")
        with op.batch_alter_table("inventory_item") as batch:
            batch.drop_column("code")
    if _inspector().has_table("stock_level"):
        op.drop_table("stock_level")
    if _inspector().has_table("stock_place"):
        op.drop_table("stock_place")
