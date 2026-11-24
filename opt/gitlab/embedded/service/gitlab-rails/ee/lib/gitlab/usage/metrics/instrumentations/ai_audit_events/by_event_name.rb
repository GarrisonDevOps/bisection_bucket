# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        module AiAuditEvents
          # Zero-filled so the PostgreSQL and ClickHouse variants report the same key set.
          module ByEventName
            private

            def empty_counts
              ::AuditEvents::AiAuditEvent::ALLOWED_EVENT_NAMES.index_with(0)
            end
          end
        end
      end
    end
  end
end
