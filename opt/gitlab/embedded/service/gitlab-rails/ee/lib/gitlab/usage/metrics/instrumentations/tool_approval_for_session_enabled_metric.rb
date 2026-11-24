# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class ToolApprovalForSessionEnabledMetric < GenericMetric
          def value
            ::Gitlab::CurrentSettings.tool_approval_for_session_enabled
          end
        end
      end
    end
  end
end
