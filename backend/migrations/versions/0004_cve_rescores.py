"""Administrator rescores of a CVE's severity and CVSS score.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-07

Mirrors the ``cve_rescores`` table in ``db.SCHEMA``.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_rescores",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("severity", sa.Text, nullable=False),
        sa.Column("cvss_score", sa.Float),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("rescored_by", sa.Text),
        sa.Column("rescored_at", sa.Text),
        sa.Column("original_severity", sa.Text),
        sa.Column("original_cvss_score", sa.Float),
    )
    op.execute("ALTER TABLE cve_rescores ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    op.drop_table("cve_rescores")
