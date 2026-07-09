"""add barcode (QR/label slug) to game

Revision ID: c1a2b3d4e5f6
Revises: 7a61de1d1679
Create Date: 2026-07-08 22:10:00.000000

Adds a stable, unique ``barcode`` slug to each game (used by the QR label /
USB-scanner lookup) and backfills a deterministic name-derived slug for every
existing row.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1a2b3d4e5f6'
down_revision = '7a61de1d1679'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add the column (nullable for now, so the backfill can populate it).
    with op.batch_alter_table('game', schema=None) as batch_op:
        batch_op.add_column(sa.Column('barcode', sa.String(length=64), nullable=True))

    # 2. Backfill a deterministic, unique slug for every existing game.
    from app.utils.helpers import generate_unique_barcode

    bind = op.get_bind()
    rows = bind.execute(sa.text("SELECT id, name FROM game ORDER BY id")).fetchall()
    taken: set[str] = set()
    for row in rows:
        slug = generate_unique_barcode(row.name or f"game-{row.id}", taken)
        bind.execute(
            sa.text("UPDATE game SET barcode = :b WHERE id = :i"),
            {"b": slug, "i": row.id},
        )

    # 3. Enforce uniqueness now that values exist.
    op.create_index('ix_game_barcode', 'game', ['barcode'], unique=True)


def downgrade():
    op.drop_index('ix_game_barcode', table_name='game')
    with op.batch_alter_table('game', schema=None) as batch_op:
        batch_op.drop_column('barcode')
