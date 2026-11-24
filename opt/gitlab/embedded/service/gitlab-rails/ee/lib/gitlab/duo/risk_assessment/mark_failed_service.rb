# frozen_string_literal: true

module Gitlab
  module Duo
    module RiskAssessment
      # Fails an assessment that nothing will submit a result for. The guard runs against
      # the locked row, so a result that lands concurrently is never erased.
      class MarkFailedService
        def initialize(assessment, guard:, log_message:, log_context: {})
          @assessment = assessment
          @guard = guard
          @log_message = log_message
          @log_context = log_context
        end

        def execute
          assessment.with_lock do
            next ServiceResponse.error(message: 'Assessment is still waiting on a result') unless guard.call(assessment)

            assessment.mark_failed

            Gitlab::AppLogger.warn(
              message: log_message,
              merge_request_id: assessment.merge_request_id,
              **log_context
            )

            ServiceResponse.success(payload: { assessment: assessment })
          end
        end

        private

        attr_reader :assessment, :guard, :log_message, :log_context
      end
    end
  end
end
