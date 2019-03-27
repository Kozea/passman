"""init

Revision ID: 52085ee4c6aa
Revises: 
Create Date: 2019-03-27 16:39:54.763782

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '52085ee4c6aa'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'group',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('label', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'user',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('login', sa.String(), nullable=False),
        sa.Column('password', sa.String(), nullable=False),
        sa.Column('public_key', sa.String(), nullable=False),
        sa.Column('private_key', sa.String(), nullable=False),
        sa.Column('nonce', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'password',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('label', sa.String(), nullable=False),
        sa.Column('login', sa.String(), nullable=False),
        sa.Column('login_tag', sa.String(), nullable=False),
        sa.Column('login_nonce', sa.String(), nullable=False),
        sa.Column('password', sa.String(), nullable=False),
        sa.Column('password_tag', sa.String(), nullable=False),
        sa.Column('password_nonce', sa.String(), nullable=False),
        sa.Column('notes', sa.String(), nullable=True),
        sa.Column('notes_tag', sa.String(), nullable=True),
        sa.Column('notes_nonce', sa.String(), nullable=True),
        sa.Column('session_key', sa.String(), nullable=False),
        sa.Column('family_key', sa.String(), nullable=False),
        sa.Column('related_user_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['related_user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'usergroup',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['group_id'], ['group.id']),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'passwordgroup',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('group_id', sa.Integer(), nullable=False),
        sa.Column('password_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['group_id'], ['group.id']),
        sa.ForeignKeyConstraint(['password_id'], ['password.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('passwordgroup')
    op.drop_table('usergroup')
    op.drop_table('request')
    op.drop_table('password')
    op.drop_table('user')
    op.drop_table('group')
    # ### end Alembic commands ###
