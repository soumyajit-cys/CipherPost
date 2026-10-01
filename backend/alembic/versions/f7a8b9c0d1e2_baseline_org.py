"""phase3: baseline_features.org_id for per-org drift

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-10-02

Nullable so legacy rows stay visible; single-tenant drift ignores the filter.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = 'f7a8b9c0d1e2'
down_revision = 'e6f7a8b9c0d1'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('baseline_features', sa.Column('org_id', sa.Text(), nullable=True))
    op.create_index('ix_baseline_features_org_ts', 'baseline_features',
                    ['org_id', 'ts'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_baseline_features_org_ts', table_name='baseline_features')
    op.drop_column('baseline_features', 'org_id')
