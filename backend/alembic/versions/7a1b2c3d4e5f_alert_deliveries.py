"""phase2: alert delivery status per channel

Revision ID: 7a1b2c3d4e5f
Revises: 2fe72d5f9ab3
Create Date: 2026-09-30

Records per-channel delivery attempts so one failing channel never blocks
others and operators can see sent/failed/attempts/last_error per alert.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from app.core.database import JSONBType as _JSONBType


revision: str = '7a1b2c3d4e5f'
down_revision = '2fe72d5f9ab3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('alert_deliveries',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('alert_id', sa.Text(), nullable=False),
    sa.Column('channel', sa.Text(), nullable=False),
    sa.Column('status', sa.Text(), nullable=False, server_default='pending'),
    sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('ts', sa.DateTime(timezone=True), server_default=sa.text('NOW()'), nullable=True),
    sa.Column('org_id', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_alert_deliveries_alert_id', 'alert_deliveries', ['alert_id'], unique=False)
    op.create_index('ix_alert_deliveries_status', 'alert_deliveries', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_alert_deliveries_status', table_name='alert_deliveries')
    op.drop_index('ix_alert_deliveries_alert_id', table_name='alert_deliveries')
    op.drop_table('alert_deliveries')
