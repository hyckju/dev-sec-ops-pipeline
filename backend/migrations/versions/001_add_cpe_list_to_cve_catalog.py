"""add cpe_list to cve_catalog

Revision ID: 001_add_cpe_list
Revises:
Create Date: 2026-03-11
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON

revision = "001_add_cpe_list"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "cve_catalog",
        sa.Column(
            "cpe_list",
            JSON,
            nullable=True,
            comment="영향받는 제품 CPE 식별자 목록",
        ),
    )


def downgrade() -> None:
    op.drop_column("cve_catalog", "cpe_list")
