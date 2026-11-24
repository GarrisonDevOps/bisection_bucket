# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        # Returns a hash of { event_name => count } for AI audit events
        class CountAiAuditEventsByEventNameClickhouseMetric < GenericMetric
          include AiAuditEvents::Clickhouse
          include AiAuditEvents::ByEventName

          private

          # Zero counts (not the -1 fallback) keep the disabled value matching
          # the object json schema.
          def disabled_value
            empty_counts
          end

          def clickhouse_value
            rows = ::ClickHouse::Client.select(
              "SELECT event_name, count() AS c FROM ai_audit_events#{time_constraint} GROUP BY event_name", :main
            )

            empty_counts.merge(rows.to_h { |row| [row['event_name'], row['c'].to_i] })
          end
        end
      end
    end
  end
end
