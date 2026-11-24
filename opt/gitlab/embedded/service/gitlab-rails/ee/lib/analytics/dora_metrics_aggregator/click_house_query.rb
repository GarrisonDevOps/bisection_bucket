# frozen_string_literal: true

module Analytics
  module DoraMetricsAggregator
    # Aggregates the replicated dora_daily_metrics rows the same way Dora::DailyMetrics.aggregate_for! does.
    class ClickHouseQuery
      DAILY_METRICS_COLUMNS = %w[environment_id date deployment_frequency lead_time_for_changes_in_seconds
        time_to_restore_service_in_seconds incidents_count].freeze

      def initialize(container:, project_ids:, metrics:, interval:, start_date:, end_date:, environment_tiers:)
        @container = container
        @project_ids = Array(project_ids).map(&:to_i)
        @metrics = metrics
        @interval = interval
        @start_date = start_date
        @end_date = end_date
        @environment_tiers = environment_tiers
      end

      def execute
        ::ClickHouse::Client.select(query, :main).map { |row| transform_row(row) }
      end

      def query
        ::ClickHouse::Client::Query.new(raw_query: raw_query, placeholders: placeholders)
      end

      private

      attr_reader :container, :project_ids, :metrics, :interval, :start_date, :end_date, :environment_tiers

      # date is part of the key and never changes, so the range is filtered before the dedup.
      def raw_query
        <<~SQL
          SELECT
            #{interval_date} AS interval_date,
            sumOrNull(daily_metrics.deployment_frequency) AS deployment_frequency,
            quantileExactInclusiveOrNull(0.5)(daily_metrics.lead_time_for_changes_in_seconds) AS lead_time_for_changes,
            quantileExactInclusiveOrNull(0.5)(daily_metrics.time_to_restore_service_in_seconds) AS time_to_restore_service,
            sumOrNull(daily_metrics.incidents_count)
              / greatest(ifNull(sumOrNull(daily_metrics.deployment_frequency), 1), 1) AS change_failure_rate
          FROM (
            SELECT
              siphon_dora_daily_metrics.id AS id,
              #{latest_columns('siphon_dora_daily_metrics', DAILY_METRICS_COLUMNS)}
            FROM siphon_dora_daily_metrics
            WHERE #{traversal_path_condition('siphon_dora_daily_metrics')}
              AND siphon_dora_daily_metrics.date BETWEEN {start_date:Date32} AND {end_date:Date32}
            GROUP BY siphon_dora_daily_metrics.id
            HAVING #{not_deleted('siphon_dora_daily_metrics')}
          ) AS daily_metrics
          INNER JOIN (
            SELECT siphon_environments.id AS id
            FROM siphon_environments
            WHERE #{traversal_path_condition('siphon_environments')}
            GROUP BY siphon_environments.id
            HAVING #{not_deleted('siphon_environments')}
              AND #{latest('siphon_environments', 'tier')} IN {tiers:Array(Int8)}
              #{"AND #{latest('siphon_environments', 'project_id')} IN {project_ids:Array(Int64)}" if project_ids.any?}
          ) AS environments ON environments.id = daily_metrics.environment_id
          #{'GROUP BY interval_date ORDER BY interval_date' unless interval == ::Dora::DailyMetrics::INTERVAL_ALL}
        SQL
      end

      def placeholders
        {
          traversal_path: traversal_path,
          start_date: start_date.iso8601,
          end_date: end_date.iso8601,
          tiers: environment_tiers.map { |tier| ::Environment.tiers.fetch(tier) },
          project_ids: project_ids
        }
      end

      # Without GROUP BY, ALL returns one row even for an empty range, like PostgreSQL does.
      def interval_date
        case interval
        when ::Dora::DailyMetrics::INTERVAL_DAILY then 'toDate(daily_metrics.date)'
        when ::Dora::DailyMetrics::INTERVAL_MONTHLY then 'toStartOfMonth(daily_metrics.date)'
        when ::Dora::DailyMetrics::INTERVAL_ALL then 'CAST(NULL AS Nullable(Date))'
        else raise ArgumentError, 'Unknown interval'
        end
      end

      # Siphon keeps one row per replicated version. argMax skips NULL values, so the column goes
      # through tuple() to keep a NULL latest value. Columns are qualified so they don't resolve to the aliases.
      def latest(table, column)
        "tupleElement(argMax(tuple(#{table}.#{column}), #{table}._siphon_replicated_at), 1)"
      end

      def latest_columns(table, columns)
        columns.map { |column| "#{latest(table, column)} AS #{column}" }.join(",\n    ")
      end

      def not_deleted(table)
        "argMax(#{table}._siphon_deleted, #{table}._siphon_replicated_at) = 0"
      end

      # Siphon stores traversal_path with the leading organization_id.
      def traversal_path_condition(table)
        if container.is_a?(::Project)
          "#{table}.traversal_path = {traversal_path:String}"
        else
          "startsWith(#{table}.traversal_path, {traversal_path:String})"
        end
      end

      def traversal_path
        namespace = container.is_a?(::Project) ? container.project_namespace : container
        namespace.traversal_path(with_organization: true)
      end

      def transform_row(row)
        date = row['interval_date']

        metrics.each_with_object({ 'date' => date && Date.parse(date.to_s) }) do |metric, result|
          value = row[metric]
          result[metric] = value && (metric == ::Dora::DeploymentFrequencyMetric::METRIC_NAME ? value.to_i : value.to_f)
        end
      end
    end
  end
end
