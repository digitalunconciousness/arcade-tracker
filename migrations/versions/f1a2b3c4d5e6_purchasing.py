"""Purchasing (inventory step 3): order-up-to levels, part deliveries, purchase orders.

Adds ``inventory_item.reorder_to`` (blank for every part: the shopping list then tops up to
twice the reorder level), ``inventory_request.quantity_received`` (0; a request already
Received is set to its full quantity, so it reads as complete), and the ``purchase_order``
and ``purchase_order_line`` tables. Purchase orders stay off until a manager turns them on.
Guarded like its neighbours, so a re-run is harmless.

Revision ID: f1a2b3c4d5e6
Revises: e0f1a2b3c4d5
"""

import sqlalchemy as sa
from alembic import op

revision = "f1a2b3c4d5e6"
down_revision = "e0f1a2b3c4d5"
branch_labels = None
depends_on = None


def _inspector():
    return sa.inspect(op.get_bind())


def _columns(table):
    return {c["name"] for c in _inspector().get_columns(table)}


def upgrade():
    bind = op.get_bind()
    if "reorder_to" not in _columns("inventory_item"):
        op.add_column("inventory_item", sa.Column("reorder_to", sa.Integer(), nullable=True))
    if "quantity_received" not in _columns("inventory_request"):
        op.add_column("inventory_request",
                      sa.Column("quantity_received", sa.Integer(), nullable=False,
                                server_default="0"))
        requests = sa.table("inventory_request", sa.column("status", sa.String),
                            sa.column("quantity_requested", sa.Integer),
                            sa.column("quantity_received", sa.Integer))
        bind.execute(requests.update().where(requests.c.status == "Received")
                     .values(quantity_received=requests.c.quantity_requested))
    if not _inspector().has_table("purchase_order"):
        op.create_table(
            "purchase_order",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("supplier_id", sa.Integer(), sa.ForeignKey("supplier.id"),
                      nullable=False),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("notes", sa.Text(), nullable=True),
            sa.Column("expected", sa.Date(), nullable=True),
            sa.Column("created_by_id", sa.Integer(),
                      sa.ForeignKey("user.id", ondelete="SET NULL",
                                    name="fk_purchase_order_created_by_id"), nullable=True),
            sa.Column("created", sa.DateTime(), nullable=False),
            sa.Column("sent", sa.DateTime(), nullable=True),
            sa.Column("closed", sa.DateTime(), nullable=True),
        )
        op.create_index("ix_purchase_order_supplier_id", "purchase_order", ["supplier_id"])
        op.create_index("ix_purchase_order_created_by_id", "purchase_order", ["created_by_id"])
    if not _inspector().has_table("purchase_order_line"):
        op.create_table(
            "purchase_order_line",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("order_id", sa.Integer(),
                      sa.ForeignKey("purchase_order.id", ondelete="CASCADE"), nullable=False),
            sa.Column("item_id", sa.Integer(), sa.ForeignKey("inventory_item.id"),
                      nullable=False),
            sa.Column("quantity", sa.Integer(), nullable=False),
            sa.Column("unit_price", sa.Float(), nullable=True),
            sa.Column("quantity_received", sa.Integer(), nullable=False, server_default="0"),
        )
        op.create_index("ix_purchase_order_line_order_id", "purchase_order_line", ["order_id"])
        op.create_index("ix_purchase_order_line_item_id", "purchase_order_line", ["item_id"])


def downgrade():
    for table in ("purchase_order_line", "purchase_order"):
        if _inspector().has_table(table):
            op.drop_table(table)
    if "quantity_received" in _columns("inventory_request"):
        with op.batch_alter_table("inventory_request") as batch:
            batch.drop_column("quantity_received")
    if "reorder_to" in _columns("inventory_item"):
        with op.batch_alter_table("inventory_item") as batch:
            batch.drop_column("reorder_to")
