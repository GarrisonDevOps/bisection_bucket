# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountAbandonedDuoWorkflowToolApprovalsMetric < DatabaseMetric
          ABANDONMENT_WINDOW = 24.hours

          operation :count

          relation do
            ::Ai::DuoWorkflows::Workflow
              .with_status(:tool_call_approval_required)
              .where(updated_at: ...ABANDONMENT_WINDOW.ago)
          end
        end
      end
    end
  end
end
