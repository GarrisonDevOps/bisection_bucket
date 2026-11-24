# frozen_string_literal: true

module Releases
  class CreateEvidenceWorker # rubocop:disable Scalability/IdempotentWorker
    include ApplicationWorker
    include CronjobChildWorker

    data_consistency :always

    sidekiq_options retry: 3

    feature_category :release_evidence
    concurrency_limit -> { 20 }
    urgency :throttled

    # pipeline_id is optional for backward compatibility with existing jobs
    # caller should always try to provide the pipeline and pass nil only
    # if pipeline is absent
    def perform(release_id, pipeline_id = nil)
      release = Release.find_by_id(release_id)

      return unless release

      pipeline = Ci::Pipeline.find_by_id(pipeline_id)

      service = ::Releases::CreateEvidenceService.new(release, pipeline: pipeline)
      return log_size_limit_exceeded(release, service.size_limit) if service.size_limit.exceeded?

      service.execute
    end

    private

    def log_size_limit_exceeded(release, size_limit)
      log_hash_metadata_on_done(
        skipped_reason: 'evidence_size_limit_exceeded',
        Labkit::Fields::GL_PROJECT_ID => release.project_id,
        evidence_bytes: size_limit.served_bytes,
        limit_bytes: size_limit.limit_bytes
      )
    end
  end
end
