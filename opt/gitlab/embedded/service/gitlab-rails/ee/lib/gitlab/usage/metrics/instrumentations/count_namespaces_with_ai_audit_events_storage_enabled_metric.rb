# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountNamespacesWithAiAuditEventsStorageEnabledMetric < DatabaseMetric
          operation :count

          relation { ::NamespaceSetting.where(ai_audit_events_storage_enabled: true) }
        end
      end
    end
  end
end
