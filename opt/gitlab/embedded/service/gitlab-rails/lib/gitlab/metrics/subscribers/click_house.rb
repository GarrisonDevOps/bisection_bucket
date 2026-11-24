# frozen_string_literal: true

module Gitlab
  module Metrics
    module Subscribers
      # Accumulates per-request totals from the `sql.click_house` events that
      # ClickHouse::Client instruments, for the structured request and Sidekiq logs,
      # and observes each query's duration as a Prometheus histogram.
      class ClickHouse < ActiveSupport::Subscriber
        extend ::Gitlab::Instrumentation::RequestStoreCounters

        attach_to :click_house

        QUERIES_COUNT = :clickhouse_queries_count
        ROWS_READ = :clickhouse_rows_read
        BYTES_READ = :clickhouse_bytes_read
        DURATION = :clickhouse_duration_s
        READ_DURATION = :clickhouse_read_duration_s
        EXECUTE_DURATION = :clickhouse_execute_duration_s

        DURATION_BUCKETS = [0.05, 0.1, 0.25, 0.5, 1.0, 3.0, 5.0, 7.0, 10.0, 20.0].freeze

        class << self
          def request_count
            counter_value(QUERIES_COUNT)
          end

          def rows_read
            counter_value(ROWS_READ)
          end

          def bytes_read
            counter_value(BYTES_READ)
          end

          def duration
            counter_duration(DURATION)
          end

          def read_duration
            counter_duration(READ_DURATION)
          end

          def execute_duration
            counter_duration(EXECUTE_DURATION)
          end

          # Empty when nothing ran, so requests without ClickHouse queries keep
          # the log line they have today.
          def payload
            return {} if request_count == 0

            {
              QUERIES_COUNT => request_count,
              ROWS_READ => rows_read,
              BYTES_READ => bytes_read,
              DURATION => duration,
              READ_DURATION => read_duration,
              EXECUTE_DURATION => execute_duration
            }
          end
        end

        def sql(event)
          # Subscribers run inside the instrumented block, so the marker is still
          # set when the event comes from ClickHouse::Client.select.
          operation = ::ClickHouse::ReadOnlyMarker.active? ? :read : :execute
          duration = event.duration / 1000.0

          add_to_request_store(event, operation, duration)
          expose_metrics(operation, duration)
        end

        private

        # The client fills `statistics` from the JSON `statistics` object on SELECT
        # (rows_read, bytes_read) and from the X-ClickHouse-Summary header otherwise
        # (read_rows, read_bytes, as strings); either may be missing.
        def add_to_request_store(event, operation, duration)
          return unless Gitlab::SafeRequestStore.active?

          statistics = event.payload[:statistics] || {}

          self.class.increment_counter(QUERIES_COUNT)
          self.class.increment_counter(ROWS_READ, (statistics[:rows_read] || statistics[:read_rows]).to_i)
          self.class.increment_counter(BYTES_READ, (statistics[:bytes_read] || statistics[:read_bytes]).to_i)
          self.class.increment_counter(DURATION, duration)
          self.class.increment_counter(operation == :read ? READ_DURATION : EXECUTE_DURATION, duration)
        end

        def expose_metrics(operation, duration)
          transaction = ::Gitlab::Metrics.current_transaction
          return unless transaction

          transaction.observe(:gitlab_clickhouse_duration_seconds, duration, { operation: operation }) do
            docstring 'ClickHouse query time'
            label_keys [:operation]
            buckets DURATION_BUCKETS
          end
        end
      end
    end
  end
end
