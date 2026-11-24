# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        # Counts distinct AI agent sessions (workflows) with AI audit events stored
        # in ClickHouse, the counterpart to
        # CountDistinctAiAgentSessionsWithAuditEventsMetric (PostgreSQL fallback store).
        class CountDistinctAiAgentSessionsWithAuditEventsClickhouseMetric < GenericMetric
          include AiAuditEvents::Clickhouse

          private

          def clickhouse_value
            ::ClickHouse::Client.select(
              "SELECT uniqExact(workflow_id) AS c FROM ai_audit_events#{time_constraint}", :main
            ).first&.fetch('c', 0).to_i
          end
        end
      end
    end
  end
end
