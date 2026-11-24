# frozen_string_literal: true

module Ci
  module PipelineProcessing
    class ReservedStageStatusCalculationService
      include Gitlab::Utils::StrongMemoize

      attr_reader :pipeline, :collection, :job

      def initialize(pipeline, collection, job)
        @pipeline = pipeline
        @collection = collection
        @job = job
      end

      def execute
        return unless apply_reserved_pre_stage_rules?

        calculate_reserved_pre_stage_status
      end

      private

      def calculate_reserved_pre_stage_status
        # This is to ensure jobs can not circumvent enforced security checks
        return 'running' unless reserved_pre_stage_completed?

        # In case the reserved pre stage failed or was canceled, we ensure subsequent jobs will skip execution
        'canceled' unless reserved_pre_stage_success?
      end

      def apply_reserved_pre_stage_rules?
        reserved_pre_stage && !job.ci_stage.reserved_pre?
      end

      def reserved_pre_stage
        pipeline.stages.find(&:reserved_pre?)
      end
      strong_memoize_attr :reserved_pre_stage

      def reserved_pre_stage_completed?
        ::Ci::HasStatus::COMPLETED_STATUSES.include?(reserved_pre_stage_status)
      end
      strong_memoize_attr :reserved_pre_stage_completed?

      def reserved_pre_stage_success?
        reserved_pre_stage_status == 'success'
      end
      strong_memoize_attr :reserved_pre_stage_success?

      def reserved_pre_stage_status
        collection.status_of_stage(reserved_pre_stage.position)
      end
      strong_memoize_attr :reserved_pre_stage_status
    end
  end
end
