# frozen_string_literal: true

module ClickHouse
  module Concerns
    # This module can be used for batching over a ClickHouse database table column
    # and do something with the yielded values. The module is responsible for
    # correctly restoring the state (cursor) in case the processing was
    # interrupted or restart the processing from the beginning of the table
    # when the table was fully processed.
    #
    # This class acts like a "template method" pattern where the implementor classes
    # need to define these methods:
    #
    # - init_context: Returns a memoized hash, initializing the context that controls the data processing.
    # - pluck_column: which column value to take from the ClickHouse DB when iterating
    # - process_collected_values: once a limit is reached or no more data, do something
    # with the collected values, issuing every mutation through execute_mutation.
    # - collect_values: filter, process and store the returned values from ClickHouse
    # - sort_key (optional): the cursor value of a plucked value; values are processed in
    # this order so the saved cursor never passes an unfinished value.
    #
    # With the `clickhouse_consistency_workers_strict_caps` flag on, the caps are enforced per value
    # and the mutations and the cursor write run inside the exclusive lease, which is renewed
    # before each of them.
    module ConsistencyWorker
      extend ActiveSupport::Concern
      include Gitlab::Utils::StrongMemoize

      LeaseLostError = Class.new(StandardError)

      MAX_RUNTIME = 150.seconds
      MAX_TTL = 5.minutes.to_i
      CLICK_HOUSE_BATCH_SIZE = 100_000
      POSTGRESQL_BATCH_SIZE = 2500
      LIMIT_STATUSES = %i[limit_reached over_time].freeze

      included do
        include Gitlab::ExclusiveLeaseHelpers
      end

      def perform
        return unless enabled?

        init_context
        runtime_limiter

        in_lock(self.class.to_s, ttl: MAX_TTL, retries: 0) do |_retried, lease|
          context[:lease] = lease
          collect_from_click_house
          finish_run if strict_caps?
        end

        finish_run unless strict_caps?
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
        raise unless strict_caps?

        metadata[:status] = :lease_taken
        log_extra_metadata_on_done(:result, metadata)
      end

      private

      attr_reader :context

      def collect_from_click_house
        click_house_each_batch do |values|
          collect_values(values)

          break if limit_was_reached?
        end
      end

      def finish_run
        process_collected_values
        renew_lease if strict_caps?

        context[:last_processed_id] = 0 if table_fully_processed?
        ClickHouse::SyncCursor.update_cursor_for(sync_cursor, context[:last_processed_id])
        log_extra_metadata_on_done(:result, metadata)
      end

      def click_house_each_batch
        iterator.each_batch(column: batch_column, of: CLICK_HOUSE_BATCH_SIZE) do |scope|
          query = scope.select(Arel.sql("DISTINCT #{pluck_column}")).to_sql
          ids_from_click_house = connection.select(query).pluck(pluck_column) # rubocop: disable CodeReuse/ActiveRecord -- limited query

          ids_from_click_house.sort_by { |value| sort_key(value) }.each_slice(POSTGRESQL_BATCH_SIZE) do |values|
            yield values
          end
        end
      end

      def execute_mutation(query)
        renew_lease if strict_caps?
        connection.execute(query)
        mutations_counter.increment({ worker: self.class.name })
      end

      # Checked before every mutation and the cursor write: a lapsed lease means another
      # run may already own the table.
      def renew_lease
        return if context[:lease].renew

        raise LeaseLostError, "#{self.class} lease expired while issuing mutations"
      end

      def mutations_counter
        @mutations_counter ||= Gitlab::Metrics.counter(
          :gitlab_clickhouse_consistency_mutations_total,
          'ALTER TABLE mutations issued by the ClickHouse consistency workers'
        )
      end

      def strict_caps?
        Feature.enabled?(:clickhouse_consistency_workers_strict_caps, :instance)
      end
      strong_memoize_attr :strict_caps?

      def sort_key(value)
        value
      end

      def enabled?
        Gitlab::ClickHouse.globally_enabled_for_analytics?
      end

      def runtime_limiter
        @runtime_limiter ||= Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
      end

      def iterator
        builder = ClickHouse::Client::QueryBuilder.new(table.to_s)
        ClickHouse::Iterator.new(query_builder: builder, connection: connection, min_value: previous_id)
      end

      def sync_cursor
        "#{table}_consistency_check"
      end

      def previous_id
        value = ClickHouse::SyncCursor.cursor_for(sync_cursor)
        value == 0 ? nil : value
      end
      strong_memoize_attr :previous_id

      def metadata
        @metadata ||= { status: :processed, modifications: 0 }
      end

      def connection
        @connection ||= ClickHouse::Connection.new(:main)
      end

      def table_fully_processed?
        metadata[:status] == :processed
      end

      def limit_was_reached?
        LIMIT_STATUSES.include?(metadata[:status])
      end
    end
  end
end
