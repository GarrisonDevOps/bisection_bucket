# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class AiAuditEventsStorageEnabledMetric < GenericMetric
          value do
            ::Gitlab::CurrentSettings.ai_audit_events_storage_enabled
          end
        end
      end
    end
  end
end
