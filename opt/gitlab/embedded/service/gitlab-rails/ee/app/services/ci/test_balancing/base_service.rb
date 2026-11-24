# frozen_string_literal: true

module Ci
  module TestBalancing
    class BaseService
      def initialize(job)
        @job = job
      end

      private

      attr_reader :job

      def validate_preconditions
        return unavailable_response unless feature_available?
        return not_parallel_response unless parallel_job?

        retention_expired_response if retention_expired?
      end

      def recover_backup
        backup = queue.backup
        return [] if backup.empty?

        persist_assignments(backup)
        queue.clear_backup

        backup
      end

      def persist_assignments(assignments)
        return if assignments.empty?

        rows = assignments.map do |item|
          {
            project_id: job.project_id,
            pipeline_id: job.pipeline_id,
            pipeline_created_at: job.pipeline.created_at,
            job_group_id: job_group.id,
            test_split_id: item[:test_split_id],
            expected_duration: item[:expected_duration],
            node_index: node_index
          }
        end

        ::Ci::TestBalancing::Assignment.insert_all(rows)
      end

      def feature_available?
        ::Feature.enabled?(:parallel_test_balancing, job.project) &&
          job.project.licensed_feature_available?(:ci_parallel_test_balancing)
      end

      def parallel_job?
        job.parallel_build? && !job.matrix_build?
      end

      def retention_expired?
        job.pipeline.created_at < ::Ci::TestBalancing::Assignment::RETENTION_PERIOD.ago
      end

      def unavailable_response
        ServiceResponse.error(message: 'Test balancing is not available for this project', reason: :feature_unavailable)
      end

      def not_parallel_response
        ServiceResponse.error(message: 'Job is not a parallel job', reason: :not_parallel)
      end

      def retention_expired_response
        ServiceResponse.error(
          message: 'Test balancing is only available within ' \
            "#{::Ci::TestBalancing::Assignment::RETENTION_PERIOD.inspect} of pipeline creation",
          reason: :retention_expired
        )
      end

      def node_index
        job.options&.dig(:instance)
      end

      def job_group
        @job_group ||= ::Ci::TestBalancing::JobGroup.find_or_create!(
          job.project_id,
          job.group_name
        )
      end

      def queue
        @queue ||= ::Ci::TestBalancing::Queue.new(
          pipeline_id: job.pipeline_id,
          job_group_id: job_group.id,
          node_index: node_index,
          node_total: job.node_total
        )
      end
    end
  end
end
