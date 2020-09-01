"""Seventh Update

Revision ID: a0b6f9dd0342
Revises: 98c3d8971d71
Create Date: 2020-08-27 16:56:14.192947

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a0b6f9dd0342'
down_revision = '98c3d8971d71'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('deployments', sa.Column('additional_outputs', sa.Text, nullable=True))
    op.add_column('deployments', sa.Column('stoutputs', sa.Text, nullable=True))
    op.add_column('deployments', sa.Column('template_type', sa.String(length=16), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    op.drop_column('deployments', 'additional_outputs')
    op.drop_column('deployments', 'stoutputs')
    op.drop_column('deployments', 'template_type')
    # ### end Alembic commands ###

