# frozen_string_literal: true

module Geo
  # Pre-aggregated verification state counts for ci_job_artifact_states,
  # partitioned into modulo-based buckets. Each row holds the total, verified,
  # and failed counts for all artifacts in that bucket.
  class CiJobArtifactVerificationSummary < Ci::ApplicationRecord
    self.table_name = 'geo_ci_job_artifact_verification_summaries'

    BUCKET_COUNT = 100_000

    enum :state, { clean: 0, dirty: 1, calculating: 2 }

    scope :state_changed_asc, -> { order(state_changed_at: :asc) }
    scope :stuck_calculating, ->(timeout) { calculating.where(state_changed_at: ...timeout.ago) }
    scope :needs_recalculation, ->(timeout) { dirty.or(stuck_calculating(timeout)) }

    validates :bucket_number, presence: true,
      numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than: BUCKET_COUNT }
  end
end
