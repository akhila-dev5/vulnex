"""Automation requests: one package's ticked CVEs, to be fixed in one pull request.

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-09

Mirrors the ``automation_requests`` table in ``db.SCHEMA``.
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "automation_requests",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("package_name", sa.Text, nullable=False),
        sa.Column("branch", sa.Text, nullable=False, server_default=""),
        sa.Column("spec_path", sa.Text, nullable=False, server_default=""),
        sa.Column("cve_ids", sa.Text, nullable=False),
        sa.Column("mode", sa.Text, nullable=False),
        sa.Column("pr_number", sa.Text, server_default=""),
        sa.Column("status", sa.Text, nullable=False, server_default="queued"),
        sa.Column("requested_by", sa.Text),
        sa.Column("requested_at", sa.Text),
    )
    op.execute("ALTER TABLE automation_requests ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.drop_table("automation_requests")
