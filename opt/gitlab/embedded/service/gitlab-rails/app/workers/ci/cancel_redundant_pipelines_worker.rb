# frozen_string_literal: true

module Ci
  class CancelRedundantPipelinesWorker
    include ApplicationWorker

    data_consistency :sticky
    feature_category :continuous_integration
    idempotent!
    deduplicate :until_executed
    urgency :low

    # GitLab.com runs this on low-urgency-ci-pipeline. 40% of its 25% default limit caps one
    # top-level group at 10% of the shard's threads. Ci::LowUrgencyCancelRedundantPipelinesWorker
    # inherits this scope and gets its own kill switch.
    concurrency_limit_scope(:root_namespace, max_percentage: 0.4,
      enabled: -> { Feature.enabled?(:ci_pipeline_execution_concurrency_limit_scope_wave_two, :instance) })

    # rubocop: disable CodeReuse/ActiveRecord -- we already use partition pruning
    def perform(pipeline_id, options = {})
      relation = Ci::Pipeline.all
      relation = relation.in_partition(options['partition_id']) if options['partition_id'].present?

      relation.find_by(id: pipeline_id).try do |pipeline|
        cancel_redundant_pipelines(pipeline)
      end
    end
    # rubocop: enable CodeReuse/ActiveRecord

    private

    def cancel_redundant_pipelines(pipeline)
      if Feature.enabled?(:ci_redundant_pipeline_cancel_from_cache, pipeline.project)
        Ci::RedundantPipelines::CancelOlderPipelinesService.for(pipeline).execute
      else
        Ci::PipelineCreation::CancelRedundantPipelinesService.new(pipeline).execute
      end
    end
  end
end
