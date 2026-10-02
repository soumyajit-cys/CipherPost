"""phase4: fingerprint columns, flow history, org allow/deny lists

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-10-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from app.core.database import JSONBType as _JSONBType


revision: str = 'b9c0d1e2f3a4'
down_revision = 'a8b9c0d1e2f3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('sessions', sa.Column('ja3', sa.String(length=32), nullable=True))
    op.add_column('sessions', sa.Column('ja4', sa.String(length=64), nullable=True))
    op.add_column('sessions', sa.Column('ja3s', sa.String(length=32), nullable=True))
    op.add_column('sessions', sa.Column('ja4s', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_sessions_ja3'), 'sessions', ['ja3'], unique=False)
    op.create_index(op.f('ix_sessions_ja4'), 'sessions', ['ja4'], unique=False)
    op.create_index(op.f('ix_sessions_ja3s'), 'sessions', ['ja3s'], unique=False)
    op.create_index(op.f('ix_sessions_ja4s'), 'sessions', ['ja4s'], unique=False)
    op.add_column('mail_flows', sa.Column('fingerprints', _JSONBType(), nullable=True))
    op.create_table('fp_lists',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('org_id', sa.String(length=64), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('fp_type', sa.String(length=16), nullable=False),
    sa.Column('value', sa.String(length=128), nullable=False),
    sa.Column('source', sa.String(length=256), nullable=False),
    sa.Column('comment', sa.Text(), nullable=False),
    sa.Column('created_by', sa.String(length=256), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_fp_lists_org_id'), 'fp_lists', ['org_id'], unique=False)
    op.create_index(op.f('ix_fp_lists_value'), 'fp_lists', ['value'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_fp_lists_value'), table_name='fp_lists')
    op.drop_index(op.f('ix_fp_lists_org_id'), table_name='fp_lists')
    op.drop_table('fp_lists')
    op.drop_column('mail_flows', 'fingerprints')
    op.drop_index(op.f('ix_sessions_ja4s'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_ja3s'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_ja4'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_ja3'), table_name='sessions')
    op.drop_column('sessions', 'ja4s')
    op.drop_column('sessions', 'ja3s')
    op.drop_column('sessions', 'ja4')
    op.drop_column('sessions', 'ja3')
