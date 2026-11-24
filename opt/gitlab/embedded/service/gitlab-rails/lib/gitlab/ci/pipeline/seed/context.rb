# frozen_string_literal: true

module Gitlab
  module Ci
    module Pipeline
      module Seed
        class Context
          TimeoutError = Class.new(StandardError)

          attr_reader :pipeline, :root_variables, :logger, :evaluated_job_candidates_count

          def initialize(pipeline, root_variables: [], logger: nil)
            @pipeline = pipeline
            @root_variables = root_variables
            @logger = logger || build_logger
            @execution_deadline = 0
            @evaluated_job_candidates_count = 0
          end

          def set_deadline(timeout_seconds)
            @execution_deadline = current_monotonic_time + timeout_seconds.to_f
          end

          # Called once per job candidate, before its rules are evaluated.
          def check_execution_time!
            raise TimeoutError, 'Timed out while evaluating rules' if execution_expired?

            @evaluated_job_candidates_count += 1
          end

          private

          attr_reader :execution_deadline

          def build_logger
            ::Gitlab::Ci::Pipeline::Logger.new(project: pipeline.project)
          end

          def current_monotonic_time
            Gitlab::Metrics::System.monotonic_time
          end

          def execution_expired?
            return false if execution_deadline == 0

            current_monotonic_time > execution_deadline
          end
        end
      end
    end
  end
end
