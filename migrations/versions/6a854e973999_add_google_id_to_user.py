"""Add google_id to user

Revision ID: 6a854e973999
Revises: ae365f9daa65
Create Date: 2024-03-18 17:31:35.937488

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6a854e973999'
down_revision = 'ae365f9daa65'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('google_id', sa.String(length=100), nullable=True))
        batch_op.create_unique_constraint(None, ['google_id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='unique')
        batch_op.drop_column('google_id')

    # ### end Alembic commands ###
