"""initial schema

Creates the four PhishGuard tables: ``scans``, ``feedback``,
``model_evaluations`` and ``dataset_sources``.

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-22
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the initial schema."""
    op.create_table('dataset_sources',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('source_url', sa.Text(), nullable=False),
    sa.Column('license', sa.String(length=128), nullable=False),
    sa.Column('retrieval_date', sa.DateTime(timezone=True), nullable=False),
    sa.Column('record_count', sa.Integer(), nullable=True),
    sa.Column('checksum_sha256', sa.String(length=64), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('model_evaluations',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('model_version', sa.String(length=64), nullable=False),
    sa.Column('feature_schema_version', sa.String(length=32), nullable=False),
    sa.Column('selected_model', sa.String(length=64), nullable=False),
    sa.Column('dataset_name', sa.String(length=255), nullable=False),
    sa.Column('dataset_license', sa.String(length=64), nullable=False),
    sa.Column('dataset_source_url', sa.Text(), nullable=False),
    sa.Column('records_used', sa.Integer(), nullable=False),
    sa.Column('test_samples', sa.Integer(), nullable=False),
    sa.Column('accuracy', sa.Float(), nullable=True),
    sa.Column('precision', sa.Float(), nullable=True),
    sa.Column('recall', sa.Float(), nullable=True),
    sa.Column('f1_score', sa.Float(), nullable=True),
    sa.Column('roc_auc', sa.Float(), nullable=True),
    sa.Column('false_positive_rate', sa.Float(), nullable=True),
    sa.Column('false_negative_rate', sa.Float(), nullable=True),
    sa.Column('metrics', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('model_evaluations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_model_evaluations_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_model_evaluations_model_version'), ['model_version'], unique=False)

    op.create_table('scans',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('submitted_url', sa.Text(), nullable=False),
    sa.Column('normalized_url', sa.Text(), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('registrable_domain', sa.String(length=255), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('analysis_coverage', sa.String(length=32), nullable=False),
    sa.Column('classification', sa.String(length=32), nullable=False),
    sa.Column('phishing_probability', sa.Float(), nullable=True),
    sa.Column('risk_score', sa.Integer(), nullable=True),
    sa.Column('model_version', sa.String(length=64), nullable=True),
    sa.Column('feature_schema_version', sa.String(length=32), nullable=True),
    sa.Column('features', sa.JSON(), nullable=True),
    sa.Column('indicators', sa.JSON(), nullable=True),
    sa.Column('warnings', sa.JSON(), nullable=True),
    sa.Column('error_code', sa.String(length=64), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('duration_ms', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_scans_classification'), ['classification'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_created_at'), ['created_at'], unique=False)
        batch_op.create_index('ix_scans_created_classification', ['created_at', 'classification'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_hostname'), ['hostname'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_registrable_domain'), ['registrable_domain'], unique=False)
        batch_op.create_index(batch_op.f('ix_scans_status'), ['status'], unique=False)
        batch_op.create_index('ix_scans_status_created', ['status', 'created_at'], unique=False)

    op.create_table('feedback',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('scan_id', sa.String(length=36), nullable=False),
    sa.Column('is_correct', sa.Boolean(), nullable=False),
    sa.Column('correct_classification', sa.String(length=32), nullable=True),
    sa.Column('comment', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_feedback_scan_id'), ['scan_id'], unique=False)

    # ### end Alembic commands ###


def downgrade() -> None:
    """Drop the initial schema."""
    with op.batch_alter_table('feedback', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_feedback_scan_id'))

    op.drop_table('feedback')
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_index('ix_scans_status_created')
        batch_op.drop_index(batch_op.f('ix_scans_status'))
        batch_op.drop_index(batch_op.f('ix_scans_registrable_domain'))
        batch_op.drop_index(batch_op.f('ix_scans_hostname'))
        batch_op.drop_index('ix_scans_created_classification')
        batch_op.drop_index(batch_op.f('ix_scans_created_at'))
        batch_op.drop_index(batch_op.f('ix_scans_classification'))

    op.drop_table('scans')
    with op.batch_alter_table('model_evaluations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_model_evaluations_model_version'))
        batch_op.drop_index(batch_op.f('ix_model_evaluations_created_at'))

    op.drop_table('model_evaluations')
    op.drop_table('dataset_sources')
    # ### end Alembic commands ###
