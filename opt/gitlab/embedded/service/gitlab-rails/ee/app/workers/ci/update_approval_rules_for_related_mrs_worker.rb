# frozen_string_literal: true

module Ci
  class UpdateApprovalRulesForRelatedMrsWorker
    include ApplicationWorker

    feature_category :code_review_workflow
    urgency :low
    data_consistency :sticky

    idempotent!

    EACH_BATCH_COUNT = 100
    MAX_BATCHES_COUNT = 20

    def perform(pipeline_id)
      pipeline = Ci::Pipeline.find_by_id(pipeline_id)
      return unless pipeline
      return if pipeline.project.approval_merge_request_rules.empty?

      # rubocop: disable CodeReuse/ActiveRecord -- To avoid N+1 queries
      merge_requests_as_base_pipeline = pipeline.merge_requests_as_base_pipeline.where.not(head_pipeline_id: nil)

      merge_requests_as_base_pipeline.each_batch(of: EACH_BATCH_COUNT) do |batch, index|
        # Limit the number of merge requests we end up updating so this
        # worker cannot run indefinitely querying and updating the database
        # This limits the amount to 2000 open MRs with a matching SHA in a project.
        break if index > MAX_BATCHES_COUNT

        head_pipelines = ::Ci::Pipeline.id_in(batch.pluck(:head_pipeline_id)).complete
        head_pipelines.each { |pipeline| ::Ci::SyncReportsToApprovalRulesService.new(pipeline).execute }
      end
      # rubocop: enable CodeReuse/ActiveRecord
    end
  end
end
