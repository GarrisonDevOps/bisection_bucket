# frozen_string_literal: true

module Utilization
  module BillableUsage
    class RefreshDailyTotalsService
      # upsert_all stamps updated_at with the writing transaction's start time, so a write
      # committing after a run can carry an updated_at older than the watermark. Re-reading
      # an hour of changed days is cheap and outlasts any transaction on this write path.
      WATERMARK_MARGIN = 1.hour

      def initialize(runtime_limiter: Gitlab::Metrics::RuntimeLimiter.new)
        @runtime_limiter = runtime_limiter
        @days_refreshed = 0
      end

      def execute
        # A lagging replica would overwrite totals with stale sums the watermark then skips.
        ::Gitlab::Database::LoadBalancing::SessionMap.current(DailyTotal.load_balancer).use_primary do
          refresh_changed_days
        end

        ServiceResponse.success(payload: { days_refreshed: days_refreshed, over_time: runtime_limiter.was_over_time? })
      end

      private

      attr_reader :runtime_limiter, :days_refreshed

      def refresh_changed_days
        watermark = DailyTotal.watermark
        since = watermark && (watermark - WATERMARK_MARGIN)

        DailyNamespaceAggregate.changed_usage_dates(since: since).each do |usage_date|
          refresh_day(usage_date)
          @days_refreshed += 1

          break if runtime_limiter.over_time?
        end
      end

      def refresh_day(usage_date)
        rows = DailyNamespaceAggregate.totals_for(usage_date).map do |total|
          {
            usage_date: total.usage_date,
            event_type: total.event_type,
            feature_qualified_name: total.feature_qualified_name,
            operation_type: total.operation_type,
            unit_of_measure: total.unit_of_measure,
            schema_version: total.schema_version,
            quantity: total.quantity,
            events_count: total.events_count,
            source_updated_at: total.updated_at
          }
        end

        DailyTotal.upsert_all(rows, unique_by: DailyTotal::UNIQUE_BY)
      end
    end
  end
end
