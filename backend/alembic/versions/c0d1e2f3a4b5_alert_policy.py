"""phase4: alert routing and per-org policy

Revision ID: c0d1e2f3a4b5
Revises: b9c0d1e2f3a4
Create Date: 2026-10-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = 'c0d1e2f3a4b5'
down_revision = 'b9c0d1e2f3a4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('alert_routes',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('org_id', sa.String(length=64), nullable=False),
    sa.Column('match_type', sa.String(length=16), nullable=False),
    sa.Column('match_value', sa.String(length=256), nullable=False),
    sa.Column('owner', sa.String(length=256), nullable=False),
    sa.Column('channel', sa.String(length=64), nullable=False),
    sa.Column('created_by', sa.String(length=256), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_alert_routes_org_id'), 'alert_routes', ['org_id'], unique=False)
    op.create_index(op.f('ix_alert_routes_match_value'), 'alert_routes', ['match_value'], unique=False)
    op.create_table('alert_policy',
    sa.Column('org_id', sa.String(length=64), nullable=False),
    sa.Column('min_severity', sa.String(length=16), nullable=False),
    sa.Column('quiet_start_hour', sa.Integer(), nullable=True),
    sa.Column('quiet_end_hour', sa.Integer(), nullable=True),
    sa.Column('quiet_tz', sa.String(length=64), nullable=False),
    sa.Column('digest', sa.String(length=16), nullable=False),
    sa.Column('updated_by', sa.String(length=256), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('org_id')
    )


def downgrade() -> None:
    op.drop_table('alert_policy')
    op.drop_index(op.f('ix_alert_routes_match_value'), table_name='alert_routes')
    op.drop_index(op.f('ix_alert_routes_org_id'), table_name='alert_routes')
    op.drop_table('alert_routes')
