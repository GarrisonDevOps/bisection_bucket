# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        # Counts distinct AI agent sessions (workflows) with AI audit events durably
        # stored in PostgreSQL; the ClickHouse population is covered by
        # CountDistinctAiAgentSessionsWithAuditEventsClickhouseMetric.
        class CountDistinctAiAgentSessionsWithAuditEventsMetric < DatabaseMetric
          operation :distinct_count, column: :workflow_id

          relation { ::AuditEvents::AiAuditEvent }

          # Batch over unfiltered workflow_id bounds: the composite index leading
          # on workflow_id serves these min/max lookups, while the defaults would
          # compute them on the time-filtered relation.
          start { ::AuditEvents::AiAuditEvent.minimum(:workflow_id) }
          finish { ::AuditEvents::AiAuditEvent.maximum(:workflow_id) }
        end
      end
    end
  end
end
