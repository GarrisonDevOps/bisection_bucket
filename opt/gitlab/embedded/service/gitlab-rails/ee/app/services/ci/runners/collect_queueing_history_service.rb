# frozen_string_literal: true

module Ci
  module Runners
    class CollectQueueingHistoryService
      ALLOWED_PERCENTILES = [50, 75, 90, 95, 99].freeze
      TIME_BUCKETS_LIMIT = (3.hours / 5.minutes) + 1 # +1 to add some error margin

      def initialize(current_user:, percentiles:, runner_type:, from_time:, to_time:, owner_namespace: nil)
        @current_user = current_user
        @percentiles = percentiles
        @runner_type = runner_type
        @from_time = from_time || 3.hours.ago.utc
        @to_time = to_time || Time.now.utc
        @owner_namespace = owner_namespace
      end

      def execute
        unless ::Gitlab::ClickHouse.configured?
          return ServiceResponse.error(message: 'ClickHouse database is not configured')
        end

        return ServiceResponse.error(message: 'Not allowed') unless allowed?

        if (to_time - from_time) / 5.minutes > TIME_BUCKETS_LIMIT
          return ServiceResponse.error(message: "Maximum of #{TIME_BUCKETS_LIMIT} 5-minute intervals can be requested")
        end

        if allowed_percentiles.empty?
          return ServiceResponse.error(
            message: "At least one of #{ALLOWED_PERCENTILES.join(', ')} percentiles should be requested")
        end

        result = with_namespace_context do
          ::ClickHouse::Client.select(clickhouse_query, :main)
        end
        ServiceResponse.success(payload: result)
      end

      private

      attr_reader :owner_namespace, :from_time, :to_time

      # Attributes the ClickHouse query to the owner namespace so its cost is
      # recorded per root namespace. owner_namespace is already a Group namespace
      # record, so it needs no conversion. A nil owner_namespace is instance-wide
      # and has no namespace to attribute.
      def with_namespace_context(&block)
        return yield unless owner_namespace

        ::Gitlab::ApplicationContext.with_context(namespace: owner_namespace, &block)
      end

      def clickhouse_query
        raw_query = <<~SQL.squish
          SELECT  started_at_bucket as time,
                  #{percentiles_query}
          FROM    #{from_table}
          WHERE   #{where_clause}
          GROUP BY started_at_bucket
          ORDER BY started_at_bucket;
        SQL

        ::ClickHouse::Client::Query.new(raw_query: raw_query, placeholders: placeholders)
      end

      def from_table
        if owner_namespace
          'ci_finished_builds_aggregated_queueing_delay_percentiles_by_owner'
        else
          'ci_finished_builds_aggregated_queueing_delay_percentiles'
        end
      end

      def placeholders
        placeholders = {
          from_time: format_datetime(from_time),
          to_time: format_datetime(to_time)
        }

        placeholders[:runner_type] = runner_type if runner_type
        placeholders[:owner_namespace_id] = owner_namespace.id if owner_namespace

        placeholders
      end

      def percentiles_query
        allowed_percentiles.map do |p|
          <<~SQL.squish
            INTERVAL quantileMerge(0.#{p})(queueing_duration_quantile) MILLISECOND as p#{p}
          SQL
        end.join(",")
      end

      def allowed_percentiles
        ALLOWED_PERCENTILES & @percentiles
      end

      def where_clause
        where_clause = <<~SQL
          status IN ['success', 'failed'] AND
          started_at_bucket >= {from_time:DateTime('UTC', 6)} AND
          started_at_bucket <= {to_time:DateTime('UTC', 6)}
        SQL

        where_clause += " AND runner_type = {runner_type:UInt8}" if runner_type
        where_clause += " AND runner_owner_namespace_id = {owner_namespace_id:UInt32}" if owner_namespace

        where_clause
      end

      def format_datetime(datetime)
        datetime&.utc&.strftime('%Y-%m-%d %H:%M:%S')
      end

      def runner_type
        ::Ci::Runner.runner_types[@runner_type]
      end

      def allowed?
        subject = owner_namespace || :global

        Ability.allowed?(@current_user, :read_jobs_statistics, subject)
      end
    end
  end
end
