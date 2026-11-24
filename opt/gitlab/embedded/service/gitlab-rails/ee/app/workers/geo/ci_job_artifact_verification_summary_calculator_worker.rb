# frozen_string_literal: true

module Geo
  class CiJobArtifactVerificationSummaryCalculatorWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- This worker does not perform work scoped to a context

    MAX_RUNTIME = 3.minutes

    idempotent!
    deduplicate :until_executed, ttl: MAX_RUNTIME

    data_consistency :sticky

    feature_category :geo_replication

    def perform
      # The summaries live in the CI database, which is read-only on a secondary
      return unless ::Gitlab::Geo.primary?
      return unless Feature.enabled?(:geo_job_artifact_verification_summaries, :instance)

      runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
      service = CiJobArtifactVerificationSummaryCalculatorService.new

      loop do
        result = service.execute
        break if result[:buckets_calculated] < CiJobArtifactVerificationSummaryCalculatorService::DIRTY_BUCKET_LIMIT
        break if runtime_limiter.over_time?
      end
    end
  end
end
