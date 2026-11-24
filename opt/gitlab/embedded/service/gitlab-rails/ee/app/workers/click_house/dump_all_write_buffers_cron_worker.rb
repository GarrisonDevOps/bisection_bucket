# frozen_string_literal: true

module ClickHouse
  class DumpAllWriteBuffersCronWorker
    include ApplicationWorker

    idempotent!
    queue_namespace :cronjob
    data_consistency :delayed
    feature_category :value_stream_management
    tags :clickhouse

    TABLES = [
      Ai::UsageEvent.clickhouse_table_name,
      AuditEvents::AiAuditEvent::CLICKHOUSE_TABLE_NAME
    ].freeze

    def perform
      return unless enabled?

      TABLES.each do |table_name|
        DumpWriteBufferWorker.perform_async(table_name)
      end
    end

    private

    def enabled?
      Gitlab::ClickHouse.globally_enabled_for_analytics?
    end
  end
end
