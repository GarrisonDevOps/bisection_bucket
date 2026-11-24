# frozen_string_literal: true

module Gitlab
  module Usage
    module Metrics
      module Instrumentations
        # Counts AI audit events durably stored in PostgreSQL. On instances using
        # ClickHouse analytics the events are written to ClickHouse instead and this
        # metric reports ~0 there; the ClickHouse population is covered by
        # CountAiAuditEventsClickhouseMetric. The `created_at` timestamp_column lets
        # the 28d frame prune monthly partitions.
        class CountAiAuditEventsMetric < DatabaseMetric
          operation :count

          timestamp_column :created_at

          relation { ::AuditEvents::AiAuditEvent }
        end
      end
    end
  end
end
