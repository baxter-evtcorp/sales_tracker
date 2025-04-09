"""Initial migration with hardcoded path

Revision ID: 249fa807b260
Revises: 
Create Date: 2025-04-07 16:08:18.882666

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '249fa807b260'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=128), nullable=False),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_user')),
    sa.UniqueConstraint('email', name=op.f('uq_user_email'))
    )
    op.create_table('deal',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=100), nullable=False),
    sa.Column('stage', sa.String(length=50), nullable=False),
    sa.Column('value', sa.Float(), nullable=False),
    sa.Column('expected_close_date', sa.Date(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('metrics', sa.Text(), nullable=True),
    sa.Column('economic_buyer', sa.Text(), nullable=True),
    sa.Column('decision_criteria', sa.Text(), nullable=True),
    sa.Column('decision_process', sa.Text(), nullable=True),
    sa.Column('paper_process', sa.Text(), nullable=True),
    sa.Column('identify_pain', sa.Text(), nullable=True),
    sa.Column('champion', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], name=op.f('fk_deal_user_id_user')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_deal'))
    )
    op.create_table('activity',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('activity_type', sa.String(length=50), nullable=False),
    sa.Column('date', sa.DateTime(), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('deal_id', sa.Integer(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.Column('contact_name', sa.String(length=100), nullable=True),
    sa.Column('company_name', sa.String(length=100), nullable=True),
    sa.ForeignKeyConstraint(['deal_id'], ['deal.id'], name=op.f('fk_activity_deal_id_deal')),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], name=op.f('fk_activity_user_id_user')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_activity'))
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('activity')
    op.drop_table('deal')
    op.drop_table('user')
    # ### end Alembic commands ###
