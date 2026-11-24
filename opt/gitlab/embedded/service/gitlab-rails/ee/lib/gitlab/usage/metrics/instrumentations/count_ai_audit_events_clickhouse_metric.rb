# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        # Counts AI audit events stored in ClickHouse. Instances using ClickHouse
        # analytics write events there instead of PostgreSQL, so this is the
        # GitLab.com-relevant counterpart to CountAiAuditEventsMetric (PostgreSQL).
        # Service Ping has no ClickHouse data source, so this runs inline during
        # generation; ClickHouse count() is cheap, so the statement-timeout concern
        # that motivates batched/deferred PostgreSQL counting does not apply.
        class CountAiAuditEventsClickhouseMetric < GenericMetric
          include AiAuditEvents::Clickhouse

          private

          def clickhouse_value
            ::ClickHouse::Client.select(
              "SELECT count() AS c FROM ai_audit_events#{time_constraint}", :main
            ).first&.fetch('c', 0).to_i
          end
        end
      end
    end
  end
end
