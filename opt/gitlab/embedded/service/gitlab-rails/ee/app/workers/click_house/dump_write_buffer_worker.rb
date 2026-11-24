# frozen_string_literal: true

module ClickHouse
  class DumpWriteBufferWorker
    include ApplicationWorker
    include ClickHouseWorker
    include LoopWithRuntimeLimit
    include Gitlab::ExclusiveLeaseHelpers

    idempotent!
    queue_namespace :click_house_buffer_sync
    data_consistency :delayed
    feature_category :value_stream_management
    tags :clickhouse
    loggable_arguments 0

    MAX_RUNTIME = 200.seconds
    BATCH_SIZE = 1000
    # The runtime limit is checked between batches, so a run can overshoot it by one insert.
    LEASE_TTL = MAX_RUNTIME + 1.minute
    # Only errors that prove the batch was not committed: a rejecting response or a connection never
    # opened. A read timeout after the body was sent is ambiguous, and re-adding a committed batch
    # would double count through the daily SummingMergeTree views, so those keep the old behaviour.
    REQUEUE_ERRORS = [
      ClickHouse::Client::DatabaseError,
      Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH, Errno::EADDRNOTAVAIL,
      Net::OpenTimeout, SocketError
    ].freeze

    INSERT_QUERY_TEMPLATE = <<~SQL.squish
      INSERT INTO %{table_name} (%{fields}) SETTINGS async_insert=1, wait_for_async_insert=1 FORMAT CSV
    SQL

    def perform(table_name)
      pending_gauge.set({ table: table_name }, ClickHouse::WriteBuffer.pending(table_name))

      return unless enabled?

      if protection_enabled?
        in_lock(lease_key(table_name), ttl: LEASE_TTL, retries: 0) { dump(table_name) }
      else
        dump(table_name)
      end
    rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
      log_extra_metadata_on_done(:result, { status: :skipped, inserted_rows: 0 })
    end

    private

    def dump(table_name)
      connection.ping # ensure CH is available

      total_inserted_rows = 0

      status = loop_with_runtime_limit(MAX_RUNTIME) do
        inserted_rows = process_next_batch(table_name)
        break :processed if inserted_rows == 0

        total_inserted_rows += inserted_rows
      end

      log_extra_metadata_on_done(:result, {
        status: status,
        inserted_rows: total_inserted_rows
      })
    end

    def pending_gauge
      Gitlab::Metrics.gauge(
        :gitlab_clickhouse_write_buffer_pending,
        'Number of events pending in the ClickHouse write buffer',
        {},
        :max
      )
    end

    def requeued_counter
      Gitlab::Metrics.counter(
        :gitlab_clickhouse_write_buffer_requeued_total,
        'Rows pushed back to the ClickHouse write buffer after a failed insert'
      )
    end

    def enabled?
      Gitlab::ClickHouse.globally_enabled_for_analytics?
    end

    def protection_enabled?
      Feature.enabled?(:clickhouse_write_buffer_dump_protection, :instance)
    end

    def lease_key(table_name)
      "#{self.class.name}:#{table_name}"
    end

    def process_next_batch(table_name)
      groups = next_batch(table_name).group_by(&:keys).values
      inserted_rows = 0

      until groups.empty?
        rows = groups.first
        inserted_rows += insert_rows(rows, mapping: build_csv_mapping(rows.first.keys), table_name: table_name)
        groups.shift
      end

      inserted_rows
    rescue *REQUEUE_ERRORS
      requeue(table_name, groups.flatten) if protection_enabled?
      raise
    end

    def requeue(table_name, rows)
      ClickHouse::WriteBuffer.add_all(table_name, rows)
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, table_name: table_name, lost_rows: rows.size)
      log_extra_metadata_on_done(:lost_rows, rows.size)
    else
      track_requeue(table_name, rows)
    end

    # Bookkeeping must never replace the insert error that process_next_batch re-raises.
    def track_requeue(table_name, rows)
      requeued_counter.increment({ table: table_name }, rows.size)
      log_extra_metadata_on_done(:requeued_rows, rows.size)
    rescue StandardError => e
      Gitlab::ErrorTracking.track_exception(e, table_name: table_name)
    end

    def next_batch(table_name)
      ClickHouse::WriteBuffer.pop(table_name, BATCH_SIZE)
    end

    def build_csv_mapping(keys)
      keys.to_h { |key| [key.to_sym, key.to_sym] }
    end

    def insert_rows(rows, mapping:, table_name:)
      CsvBuilder::Gzip.new(rows, mapping).render do |tempfile|
        connection.insert_csv(prepare_insert_statement(mapping, table_name), File.open(tempfile.path))
        rows.size
      end
    end

    def prepare_insert_statement(mapping, table_name)
      format(INSERT_QUERY_TEMPLATE, fields: mapping.keys.join(', '), table_name: table_name)
    end

    def connection
      @connection ||= ClickHouse::Connection.new(:main)
    end
  end
end
