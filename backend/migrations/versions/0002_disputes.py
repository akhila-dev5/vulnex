"""Dispute requests (raised by developers, approved by the administrator).

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-04

Mirrors the ``disputes`` table in ``db.SCHEMA``.
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "disputes",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("cve_id", sa.Text, nullable=False),
        sa.Column("branch", sa.Text, nullable=False, server_default=""),
        sa.Column("spec_path", sa.Text, nullable=False, server_default=""),
        sa.Column("package_name", sa.Text),
        sa.Column("package_version", sa.Text),
        sa.Column("severity", sa.Text),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("first_unaffected_version", sa.Text, server_default=""),
        sa.Column("never_applicable", sa.Integer, server_default="0"),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.Text),
        sa.Column("requested_at", sa.Text),
        sa.Column("decided_by", sa.Text, server_default=""),
        sa.Column("decided_at", sa.Text),
        sa.Column("decision_note", sa.Text, server_default=""),
    )
    op.create_index("idx_disputes_status", "disputes", ["status"])
    op.create_index("idx_disputes_key", "disputes", ["cve_id", "branch", "spec_path"])
    # Same as the other tables: the app uses a direct connection, the public API sees nothing.
    op.execute("ALTER TABLE disputes ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.drop_table("disputes")
