# frozen_string_literal: true

module Security
  class ProcessScanEventsWorker
    include ApplicationWorker

    idempotent!
    data_consistency :delayed

    worker_resource_boundary :cpu
    sidekiq_options retry: 3
    include SecurityScansQueue

    feature_category :vulnerability_management

    def perform(pipeline_id)
      pipeline = ::Ci::Pipeline.find_by_id(pipeline_id)
      return unless pipeline

      ::Security::ProcessScanEventsService.execute(pipeline)
    end
  end
end
