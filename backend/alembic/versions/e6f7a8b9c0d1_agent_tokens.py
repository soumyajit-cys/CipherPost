"""phase3: agent_tokens for org-scoped sensors

Revision ID: e6f7a8b9c0d1
Revises: d5e6f7a8b9c0
Create Date: 2026-10-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = 'e6f7a8b9c0d1'
down_revision = 'd5e6f7a8b9c0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('agent_tokens',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('org_id', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('key_hash', sa.String(length=128), nullable=False),
    sa.Column('prefix', sa.String(length=16), nullable=False),
    sa.Column('revoked', sa.Boolean(), server_default='false', nullable=False),
    sa.Column('created_by', sa.String(length=256), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_agent_tokens_key_hash'), 'agent_tokens', ['key_hash'], unique=True)
    op.create_index(op.f('ix_agent_tokens_org_id'), 'agent_tokens', ['org_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_agent_tokens_org_id'), table_name='agent_tokens')
    op.drop_index(op.f('ix_agent_tokens_key_hash'), table_name='agent_tokens')
    op.drop_table('agent_tokens')
