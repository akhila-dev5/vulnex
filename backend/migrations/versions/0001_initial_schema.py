"""Initial schema: scan snapshot, triage trail, assignments, CVE cache.

Revision ID: 0001
Revises:
Create Date: 2026-11-01

Mirrors ``db.SCHEMA`` (the SQLite schema) column for column. Timestamps stay
ISO-8601 text and JSON blobs stay text, exactly as the application writes them,
so the same queries run on both databases (tests/test_postgres.py checks the two
schemas have not drifted).
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def _id():
    return sa.Column("id", sa.Integer, primary_key=True, autoincrement=True)


def upgrade() -> None:
    op.create_table(
        "scans",
        _id(),
        sa.Column("started_at", sa.Text, nullable=False),
        sa.Column("finished_at", sa.Text),
        sa.Column("branches", sa.Text),
        sa.Column("ecosystem", sa.Text),
        sa.Column("package_count", sa.Integer, server_default="0"),
        sa.Column("finding_count", sa.Integer, server_default="0"),
        sa.Column("affected_count", sa.Integer, server_default="0"),
        sa.Column("patched_count", sa.Integer, server_default="0"),
        sa.Column("false_positive_count", sa.Integer, server_default="0"),
        sa.Column("unconfirmed_count", sa.Integer, server_default="0"),
        sa.Column("status", sa.Text, server_default="running"),
        sa.Column("message", sa.Text),
        sa.Column("duration_seconds", sa.Float),
    )
    op.create_table(
        "packages",
        _id(),
        sa.Column("scan_id", sa.Integer),
        sa.Column("branch", sa.Text),
        sa.Column("name", sa.Text),
        sa.Column("version", sa.Text),
        sa.Column("release", sa.Text),
        sa.Column("epoch", sa.Integer, server_default="0"),
        sa.Column("evr", sa.Text),
        sa.Column("summary", sa.Text),
        sa.Column("license", sa.Text),
        sa.Column("url", sa.Text),
        sa.Column("group_name", sa.Text),
        sa.Column("spec_path", sa.Text),
        sa.Column("spec_url", sa.Text),
        sa.Column("source0_url", sa.Text),
        sa.Column("source_urls", sa.Text),
        sa.Column("tarball_name", sa.Text),
        sa.Column("tarball_url", sa.Text),
        sa.Column("tarball_available", sa.Integer),
        sa.Column("patch_count", sa.Integer, server_default="0"),
        sa.Column("is_primary", sa.Integer, server_default="1"),
        sa.UniqueConstraint("branch", "spec_path"),
    )
    op.create_table(
        "patches",
        _id(),
        sa.Column("scan_id", sa.Integer),
        sa.Column("package_name", sa.Text),
        sa.Column("branch", sa.Text),
        sa.Column("spec_path", sa.Text),
        sa.Column("tag", sa.Text),
        sa.Column("filename", sa.Text),
        sa.Column("cve_ids", sa.Text),
        sa.Column("is_nopatch", sa.Integer, server_default="0"),
        sa.Column("file_present", sa.Integer),
        sa.Column("status", sa.Text),
        sa.Column("comment", sa.Text),
    )
    op.create_table(
        "findings",
        _id(),
        sa.Column("scan_id", sa.Integer),
        sa.Column("cve_id", sa.Text),
        sa.Column("package_name", sa.Text),
        sa.Column("package_version", sa.Text),
        sa.Column("branch", sa.Text),
        sa.Column("spec_path", sa.Text),
        sa.Column("status", sa.Text),
        sa.Column("severity", sa.Text),
        sa.Column("cvss_score", sa.Float),
        sa.Column("cvss_vector", sa.Text),
        sa.Column("confidence", sa.Float),
        sa.Column("description", sa.Text),
        sa.Column("fixed_version", sa.Text),
        sa.Column("advisory_id", sa.Text),
        sa.Column("source", sa.Text),
        sa.Column("refs", sa.Text),
        sa.Column("upstream_fix", sa.Text),
        sa.Column("patch_name", sa.Text),
        sa.Column("patch_status", sa.Text),
        sa.Column("fixed_in", sa.Text),
        sa.Column("fixed_in_basis", sa.Text),
        sa.Column("fix_source", sa.Text),
        sa.Column("affected_files", sa.Text),
        sa.Column("corroborating_sources", sa.Text),
        sa.Column("evidence", sa.Text),
        sa.Column("raw_sources", sa.Text),
        sa.UniqueConstraint("cve_id", "branch", "spec_path"),
    )
    op.create_table(
        "assignments",
        _id(),
        sa.Column("cve_id", sa.Text),
        sa.Column("package_name", sa.Text),
        sa.Column("target_repo", sa.Text),
        sa.Column("status", sa.Text, server_default="queued"),
        sa.Column("notes", sa.Text),
        sa.Column("assignee_email", sa.Text, server_default=""),
        sa.Column("created_at", sa.Text),
        sa.Column("updated_at", sa.Text),
        sa.UniqueConstraint("cve_id", "package_name"),
    )
    op.create_table(
        "assignment_comments",
        _id(),
        sa.Column("assignment_id", sa.Integer, nullable=False),
        sa.Column("author", sa.Text),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text),
    )
    op.create_table(
        "finding_triage",
        _id(),
        sa.Column("cve_id", sa.Text, nullable=False),
        sa.Column("branch", sa.Text, nullable=False, server_default=""),
        sa.Column("spec_path", sa.Text, nullable=False, server_default=""),
        sa.Column("package_name", sa.Text),
        sa.Column("triage_status", sa.Text, server_default="open"),
        sa.Column("resolution_status", sa.Text, server_default=""),
        sa.Column("final_verdict", sa.Text, server_default=""),
        sa.Column("patch_link", sa.Text, server_default=""),
        sa.Column("available_since", sa.Text, server_default=""),
        sa.Column("github_pr_number", sa.Text, server_default=""),
        sa.Column("github_pr_url", sa.Text, server_default=""),
        sa.Column("github_pr_set_by", sa.Text, server_default=""),
        sa.Column("github_pr_set_at", sa.Text),
        sa.Column("owner", sa.Text, server_default=""),
        sa.Column("vuln_id", sa.Text, server_default=""),
        sa.Column("qualys_ids", sa.Text, server_default=""),
        sa.Column("updated_at", sa.Text),
        sa.UniqueConstraint("cve_id", "branch", "spec_path"),
    )
    op.create_table(
        "finding_comments",
        _id(),
        sa.Column("cve_id", sa.Text, nullable=False),
        sa.Column("branch", sa.Text, nullable=False, server_default=""),
        sa.Column("spec_path", sa.Text, nullable=False, server_default=""),
        sa.Column("kind", sa.Text, server_default="comment"),
        sa.Column("author", sa.Text),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("created_at", sa.Text),
    )
    op.create_table(
        "cve_cache",
        sa.Column("cve_id", sa.Text, primary_key=True),
        sa.Column("payload", sa.Text),
        sa.Column("fetched_at", sa.Text),
    )

    op.create_index("idx_findings_status", "findings", ["status"])
    op.create_index("idx_findings_severity", "findings", ["severity"])
    op.create_index("idx_findings_package", "findings", ["package_name"])
    op.create_index("idx_findings_cve", "findings", ["cve_id"])
    op.create_index("idx_patches_package", "patches", ["package_name"])
    op.create_index("idx_packages_name", "packages", ["name"])
    op.create_index("idx_findings_spec", "findings", ["branch", "spec_path"])
    op.create_index("idx_comments_assignment", "assignment_comments", ["assignment_id"])
    op.create_index("idx_triage_key", "finding_triage", ["cve_id", "branch", "spec_path"])
    op.create_index("idx_finding_comments_key", "finding_comments", ["cve_id", "branch", "spec_path"])

    # Supabase exposes every public table through its REST API by default. This
    # app talks to Postgres directly, so switch row-level security on with no
    # policies: the public (anon/authenticated) API roles then see nothing.
    # The connection role used by the backend owns the tables and bypasses it.
    for table in (
        "scans", "packages", "patches", "findings", "assignments",
        "assignment_comments", "finding_triage", "finding_comments", "cve_cache",
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    for table in (
        "cve_cache", "finding_comments", "finding_triage", "assignment_comments",
        "assignments", "findings", "patches", "packages", "scans",
    ):
        op.drop_table(table)
