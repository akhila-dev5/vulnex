"""When a finding was first scanned.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-06

Mirrors ``findings.first_seen`` in ``db.SCHEMA``. Existing rows stay NULL until the next
scan sync copies the dates recorded in the scan snapshot.
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("first_seen", sa.Text))


def downgrade() -> None:
    op.drop_column("findings", "first_seen")
