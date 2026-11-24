# frozen_string_literal: true

class RemoveRiskAssessmentTimeoutWorkerJobInstances < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  DEPRECATED_JOB_CLASSES = %w[
    Ai::RiskAssessment::TimeoutWorker
    Ai::RiskClassification::TimeoutWorker
  ]

  def up
    sidekiq_remove_jobs(job_klasses: DEPRECATED_JOB_CLASSES)
  end

  def down
    # This migration removes any instances of deprecated workers and cannot be undone.
  end
end
