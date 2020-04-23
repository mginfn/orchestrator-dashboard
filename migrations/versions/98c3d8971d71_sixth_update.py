"""Sixth Update.

Revision ID: 98c3d8971d71
Revises: 98c3d8971d70
Create Date: 2020-04-23
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = '98c3d8971d71'
down_revision = '98c3d8971d70'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('deployments', sa.Column('deployment_type', sa.String(length=16), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    op.drop_column('deployments', 'deployment_type')
    # ### end Alembic commands ###
