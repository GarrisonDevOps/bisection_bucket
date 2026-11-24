# frozen_string_literal: true

module Analytics
  # Backfills usage data to ClickHouse from Postgres when ClickHouse was enabled for analytics
  class AiUsageEventsBackfillWorker < ClickHouse::SyncStrategies::BaseSyncStrategy
    include Gitlab::EventStore::Subscriber

    data_consistency :sticky
    feature_category :value_stream_management
    tags :clickhouse
    urgency :low
    idempotent!
    defer_on_database_health_signal :gitlab_main

    RESCHEDULING_DELAY = 1.minute

    def handle_event(event)
      execute.tap do |result|
        log_extra_metadata_on_done(:result, result)

        if !result[:reached_end_of_table] && result[:status] != :disabled
          self.class.perform_in(RESCHEDULING_DELAY, event.class.name, event.data.deep_stringify_keys.to_h)
        end
      end
    end

    private

    def model_class
      ::Ai::UsageEvent
    end

    def projections
      @projections ||= [
        :id,
        "EXTRACT(epoch FROM timestamp) AS casted_timestamp",
        :user_id,
        "event as raw_event",
        :namespace_id,
        :extras
      ]
    end

    def csv_mapping
      @csv_mapping ||= {
        user_id: :user_id,
        timestamp: :casted_timestamp,
        event: :raw_event,
        namespace_path: :namespace_path,
        traversal_path: :traversal_path,
        extras: :raw_extras
      }
    end

    def transform_row(row)
      row.attributes.symbolize_keys.slice(*csv_mapping.values).tap do |result|
        result[:raw_extras] = row['extras'].to_json
        result[:namespace_path] = row.namespace&.traversal_path(with_organization: false)
        result[:traversal_path] = row.namespace&.traversal_path(with_organization: true)
      end
    end

    def batching_scope
      super.with_namespace
    end

    def enabled?
      super && ApplicationSetting.current_without_cache.use_clickhouse_for_analytics?
    end

    def insert_query
      <<~SQL.squish
          INSERT INTO #{model_class.clickhouse_table_name} (#{csv_mapping.keys.join(', ')})
          SETTINGS async_insert=1, wait_for_async_insert=1 FORMAT CSV
      SQL
    end
  end
end
