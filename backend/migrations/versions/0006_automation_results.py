"""Automation requests: when they ran, the PR they raised and a message.

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-10
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in ("started_at", "finished_at"):
        op.add_column("automation_requests", sa.Column(column, sa.Text))
    for column in ("pr_url", "branch_name", "message"):
        op.add_column("automation_requests", sa.Column(column, sa.Text, server_default=""))


def downgrade() -> None:
    for column in ("message", "branch_name", "pr_url", "finished_at", "started_at"):
        op.drop_column("automation_requests", column)
