"""phase2: retention support (legal_hold, timestamps, purge indexes)

Revision ID: b3c4d5e6f7a8
Revises: 9c2d3e4f5a6b
Create Date: 2026-09-30

- legal_hold on analysis_jobs + findings (survive retention purges)
- created_at on sessions + findings (nullable so legacy rows are never
  purged by accident; new writes set it)
- indexes for retention deletes and history queries
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = 'b3c4d5e6f7a8'
down_revision = '9c2d3e4f5a6b'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('analysis_jobs', sa.Column('legal_hold', sa.Boolean(), server_default='false', nullable=False))
    op.add_column('findings', sa.Column('legal_hold', sa.Boolean(), server_default='false', nullable=False))
    op.add_column('sessions', sa.Column('created_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('findings', sa.Column('created_at', sa.DateTime(timezone=True), nullable=True))
    op.create_index('ix_sessions_created_at', 'sessions', ['created_at'], unique=False)
    op.create_index('ix_sessions_org_created', 'sessions', ['org_id', 'created_at'], unique=False)
    op.create_index('ix_findings_created_at', 'findings', ['created_at'], unique=False)
    op.create_index('ix_alerts_ts', 'alerts', ['ts'], unique=False)
    op.create_index('ix_alerts_org_ts', 'alerts', ['org_id', 'ts'], unique=False)
    op.create_index('ix_audit_log_created_at', 'audit_log', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_audit_log_created_at', table_name='audit_log')
    op.drop_index('ix_alerts_org_ts', table_name='alerts')
    op.drop_index('ix_alerts_ts', table_name='alerts')
    op.drop_index('ix_findings_created_at', table_name='findings')
    op.drop_index('ix_sessions_org_created', table_name='sessions')
    op.drop_index('ix_sessions_created_at', table_name='sessions')
    op.drop_column('findings', 'created_at')
    op.drop_column('sessions', 'created_at')
    op.drop_column('findings', 'legal_hold')
    op.drop_column('analysis_jobs', 'legal_hold')
