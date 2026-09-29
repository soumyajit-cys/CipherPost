"""phase2: suppressions table for accepted-risk exceptions

Revision ID: 9c2d3e4f5a6b
Revises: 7a1b2c3d4e5f
Create Date: 2026-09-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from app.core.database import JSONBType as _JSONBType


revision: str = '9c2d3e4f5a6b'
down_revision = '7a1b2c3d4e5f'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('suppressions',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('org_id', sa.String(length=64), nullable=False),
    sa.Column('rule_id', sa.String(length=128), nullable=False),
    sa.Column('scope', _JSONBType(), nullable=False),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.Column('created_by', sa.String(length=256), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_suppressions_org_id'), 'suppressions', ['org_id'], unique=False)
    op.create_index(op.f('ix_suppressions_rule_id'), 'suppressions', ['rule_id'], unique=False)
    op.create_index(op.f('ix_suppressions_status'), 'suppressions', ['status'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_suppressions_status'), table_name='suppressions')
    op.drop_index(op.f('ix_suppressions_rule_id'), table_name='suppressions')
    op.drop_index(op.f('ix_suppressions_org_id'), table_name='suppressions')
    op.drop_table('suppressions')
