"""phase2: mail_flows table for per-flow posture

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-09-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from app.core.database import JSONBType as _JSONBType


revision: str = 'c4d5e6f7a8b9'
down_revision = 'b3c4d5e6f7a8'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('mail_flows',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('org_id', sa.String(length=64), nullable=False),
    sa.Column('client_host', sa.String(length=256), nullable=False),
    sa.Column('server_host', sa.String(length=256), nullable=False),
    sa.Column('protocol', sa.String(length=16), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('total_sessions', sa.Integer(), nullable=False),
    sa.Column('encrypted_sessions', sa.Integer(), nullable=False),
    sa.Column('plaintext_sessions', sa.Integer(), nullable=False),
    sa.Column('versions', _JSONBType(), nullable=True),
    sa.Column('ciphers', _JSONBType(), nullable=True),
    sa.Column('best_version', sa.String(length=32), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_mail_flows_org_seen', 'mail_flows', ['org_id', 'last_seen'], unique=False)
    op.create_index('ix_mail_flows_org_server', 'mail_flows', ['org_id', 'server_host'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_mail_flows_org_server', table_name='mail_flows')
    op.drop_index('ix_mail_flows_org_seen', table_name='mail_flows')
    op.drop_table('mail_flows')
