"""add group id in password

Revision ID: 5ff3fac991ae
Revises: ee886e73f961
Create Date: 2019-03-07 11:10:04.495268

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '5ff3fac991ae'
down_revision = 'ee886e73f961'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('password') as batch_op:
        batch_op.add_column(sa.Column('group_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('password', 'group', ['group_id'], ['id'])


def downgrade():
    with op.batch_alter_table('password') as batch_op:
        batch_op.drop_constraint('password', type_='foreignkey')
        batch_op.drop_column('group_id')
