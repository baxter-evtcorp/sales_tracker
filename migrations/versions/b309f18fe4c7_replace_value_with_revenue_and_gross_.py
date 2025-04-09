"""Replace value with revenue and gross_profit in Deal

Revision ID: b309f18fe4c7
Revises: 249fa807b260
Create Date: 2025-04-08 20:15:30.758650

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b309f18fe4c7'
down_revision = '249fa807b260'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('deal', schema=None) as batch_op:
        batch_op.add_column(sa.Column('revenue', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('gross_profit', sa.Float(), nullable=True))
        batch_op.drop_column('value')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('deal', schema=None) as batch_op:
        batch_op.add_column(sa.Column('value', sa.FLOAT(), nullable=False))
        batch_op.drop_column('gross_profit')
        batch_op.drop_column('revenue')

    # ### end Alembic commands ###
