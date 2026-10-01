"""phase3: user auth fields (mfa, oidc, session version, platform admin)

Revision ID: d5e6f7a8b9c0
Revises: c4d5e6f7a8b9
Create Date: 2026-10-02

All new columns default to deny/local-only: mfa off, no OIDC binding,
session_version 1, not a platform admin.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from app.core.database import JSONBType as _JSONBType


revision: str = 'd5e6f7a8b9c0'
down_revision = 'c4d5e6f7a8b9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('mfa_secret_enc', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), server_default='false', nullable=False))
    op.add_column('users', sa.Column('mfa_recovery', _JSONBType(), nullable=True))
    op.add_column('users', sa.Column('oidc_sub', sa.String(length=256), nullable=True))
    op.add_column('users', sa.Column('session_version', sa.Integer(), server_default='1', nullable=False))
    op.add_column('users', sa.Column('is_platform_admin', sa.Boolean(), server_default='false', nullable=False))
    op.create_index(op.f('ix_users_oidc_sub'), 'users', ['oidc_sub'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_users_oidc_sub'), table_name='users')
    op.drop_column('users', 'is_platform_admin')
    op.drop_column('users', 'session_version')
    op.drop_column('users', 'oidc_sub')
    op.drop_column('users', 'mfa_recovery')
    op.drop_column('users', 'mfa_enabled')
    op.drop_column('users', 'mfa_secret_enc')
