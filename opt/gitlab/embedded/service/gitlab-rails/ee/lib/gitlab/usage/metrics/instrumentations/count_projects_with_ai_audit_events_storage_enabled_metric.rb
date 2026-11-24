# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        class CountProjectsWithAiAuditEventsStorageEnabledMetric < DatabaseMetric
          operation :count

          relation { ::ProjectSetting.where(ai_audit_events_storage_enabled: true) }
        end
      end
    end
  end
end
