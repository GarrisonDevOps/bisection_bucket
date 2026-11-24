# frozen_string_literal: true

module EE
  module Ci
    module PipelineProcessing
      module AtomicProcessingService
        extend ::Gitlab::Utils::Override

        private

        override :status_of_previous_jobs
        def status_of_previous_jobs(job)
          ::Ci::PipelineProcessing::ReservedStageStatusCalculationService.new(
            pipeline, collection, job).execute || super
        end
      end
    end
  end
end
