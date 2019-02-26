"""init

Revision ID: ee886e73f961
Revises: 
Create Date: 2019-02-21 18:31:37.008182

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ee886e73f961'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('mail', sa.String(), nullable=False),
        sa.Column('password', sa.String(), nullable=False),
        sa.Column('public_key', sa.String(), nullable=False),
        sa.Column('private_key', sa.String(), nullable=False),
        sa.Column('nonce', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table('group',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('label', sa.String(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['owner_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table('password',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('label', sa.String(), nullable=False),
        sa.Column('login', sa.String(), nullable=False),
        sa.Column('login_tag', sa.String(), nullable=False),
        sa.Column('login_nonce', sa.String(), nullable=False),
        sa.Column('password', sa.String(), nullable=False),
        sa.Column('password_tag', sa.String(), nullable=False),
        sa.Column('password_nonce', sa.String(), nullable=False),
        sa.Column('questions', sa.String(), nullable=True),
        sa.Column('questions_tag', sa.String(), nullable=True),
        sa.Column('questions_nonce', sa.String(), nullable=True),
        sa.Column('session_key', sa.String(), nullable=False),
        sa.Column('owner_id', sa.Integer(), nullable=False),
        sa.Column('have_access_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['have_access_id'], ['user.id'], ),
        sa.ForeignKeyConstraint(['owner_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table('grouprequest',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token', sa.String(), nullable=False),
        sa.Column('timestamp', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['group_id'], ['group.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_table('usergroup',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['group_id'], ['group.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade():
    op.drop_table('usergroup')
    op.drop_table('grouprequest')
    op.drop_table('password')
    op.drop_table('group')
    op.drop_table('user')
