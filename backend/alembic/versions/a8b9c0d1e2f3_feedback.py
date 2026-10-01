"""phase3: finding_feedback labels for analyst review

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-10-02
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = 'a8b9c0d1e2f3'
down_revision = 'f7a8b9c0d1e2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('finding_feedback',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('org_id', sa.String(length=64), nullable=False),
    sa.Column('finding_id', sa.Integer(), nullable=True),
    sa.Column('rule_id', sa.String(length=128), nullable=False),
    sa.Column('session_id', sa.String(length=64), nullable=True),
    sa.Column('verdict', sa.String(length=32), nullable=False),
    sa.Column('comment', sa.Text(), nullable=False),
    sa.Column('created_by', sa.String(length=256), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_finding_feedback_finding_id'), 'finding_feedback', ['finding_id'], unique=False)
    op.create_index(op.f('ix_finding_feedback_org_id'), 'finding_feedback', ['org_id'], unique=False)
    op.create_index(op.f('ix_finding_feedback_rule_id'), 'finding_feedback', ['rule_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_finding_feedback_rule_id'), table_name='finding_feedback')
    op.drop_index(op.f('ix_finding_feedback_org_id'), table_name='finding_feedback')
    op.drop_index(op.f('ix_finding_feedback_finding_id'), table_name='finding_feedback')
    op.drop_table('finding_feedback')
