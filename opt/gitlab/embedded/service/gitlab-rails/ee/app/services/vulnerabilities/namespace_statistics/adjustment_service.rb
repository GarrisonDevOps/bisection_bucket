# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class AdjustmentService
      include Gitlab::InternalEventsTracking
      include Security::NamespaceTraversalSqlBuilder

      TooManyNamespacesError = Class.new(StandardError)

      UPSERT_SQL = <<~SQL
        INSERT INTO vulnerability_namespace_statistics
          (total, info, unknown, low, medium, high, critical, traversal_ids, namespace_id, created_at, updated_at)
          (%{new_values})
        ON CONFLICT (namespace_id)
        DO UPDATE SET
          total = EXCLUDED.total,
          info = EXCLUDED.info,
          unknown = EXCLUDED.unknown,
          low = EXCLUDED.low,
          medium = EXCLUDED.medium,
          high = EXCLUDED.high,
          critical = EXCLUDED.critical,
          updated_at = EXCLUDED.updated_at,
          traversal_ids = EXCLUDED.traversal_ids
        RETURNING namespace_id
      SQL

      STATS_SQL = <<~SQL
        WITH namespace_data (namespace_id, traversal_ids, next_traversal_id) AS (
            %{with_values}
        )
        SELECT
          COALESCE(SUM(vulnerability_statistics.total), 0) AS total,
          COALESCE(SUM(vulnerability_statistics.info), 0) AS info,
          COALESCE(SUM(vulnerability_statistics.unknown), 0) AS unknown,
          COALESCE(SUM(vulnerability_statistics.low), 0) AS low,
          COALESCE(SUM(vulnerability_statistics.medium), 0) AS medium,
          COALESCE(SUM(vulnerability_statistics.high), 0) AS high,
          COALESCE(SUM(vulnerability_statistics.critical), 0) AS critical,
          namespace_data.traversal_ids as traversal_ids,
          namespace_data.namespace_id as namespace_id,
          now() AS created_at,
          now() AS updated_at
        FROM namespace_data
        LEFT JOIN vulnerability_statistics
          ON vulnerability_statistics.archived = FALSE
          AND vulnerability_statistics.traversal_ids >= namespace_data.traversal_ids
          AND vulnerability_statistics.traversal_ids < namespace_data.next_traversal_id
        GROUP BY namespace_data.traversal_ids, namespace_id
        ORDER BY namespace_data.traversal_ids, namespace_id
      SQL

      SELECT_NEW_VALUES_SQL = <<~SQL
        SELECT total, info, unknown, low, medium, high, critical, traversal_ids, namespace_id, created_at, updated_at
        FROM new_values
        ORDER BY namespace_id
      SQL

      OLD_VALUES_SQL = <<~SQL
        SELECT
          namespace_id,
          traversal_ids,
          total,
          critical,
          high,
          medium,
          low,
          unknown,
          info
        FROM vulnerability_namespace_statistics
        WHERE namespace_id IN (SELECT namespace_id FROM new_values)
        ORDER BY namespace_id
      SQL

      NAMESPACE_DIFF_SQL = <<~SQL
        SELECT
          new_values.namespace_id AS namespace_id,
          new_values.traversal_ids,
          new_values.total - COALESCE(old_values.total, 0) AS total,
          new_values.info - COALESCE(old_values.info, 0) AS info,
          new_values.unknown - COALESCE(old_values.unknown, 0) AS unknown,
          new_values.low - COALESCE(old_values.low, 0) AS low,
          new_values.medium - COALESCE(old_values.medium, 0) AS medium,
          new_values.high - COALESCE(old_values.high, 0) AS high,
          new_values.critical - COALESCE(old_values.critical, 0) AS critical
        FROM new_values
        LEFT JOIN old_values
          ON new_values.namespace_id = old_values.namespace_id
        WHERE EXISTS (
          SELECT 1
          FROM upserted
          WHERE upserted.namespace_id = new_values.namespace_id
        )
        ORDER BY new_values.namespace_id
      SQL

      UPSERT_WITH_DIFF_SQL = <<~SQL
        WITH new_values AS (
          %{stats_sql}
        ), old_values AS (
          %{old_values_sql}
        ), upserted AS (
          %{upsert_sql}
        ), diff_values AS (
          %{diff_sql}
        )
        SELECT *
        FROM diff_values
        WHERE
          total != 0 OR
          info != 0 OR
          unknown != 0 OR
          low != 0 OR
          medium != 0 OR
          high != 0 OR
          critical != 0
        ORDER BY namespace_id
      SQL

      MAX_NAMESPACES = 1_000

      def self.execute(namespace_ids)
        new(namespace_ids).execute
      end

      def initialize(namespace_ids)
        if namespace_ids.size > MAX_NAMESPACES
          raise TooManyNamespacesError, "Cannot adjust namespace statistics for more than #{MAX_NAMESPACES} namespaces"
        end

        @namespace_ids = namespace_ids
      end

      def execute
        all_diffs = []
        return all_diffs if @namespace_ids.empty?

        @namespace_ids.each_slice(100) do |namespace_ids_batch|
          namespace_data = with_namespace_data(namespace_ids_batch)
          next if namespace_data.blank?

          diffs = connection.execute(upsert_with_diffs_sql(namespace_data))
          all_diffs.concat(non_zero_diffs(diffs.to_a))
        end

        if all_diffs.present?
          # rubocop:disable CodeReuse/ActiveRecord -- collect namespace ids in single query
          # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- we limit the number of namespaces in the service
          namespace_ids = all_diffs.pluck('namespace_id')
          # rubocop:enable Database/AvoidUsingPluckWithoutLimit
          # rubocop:enable CodeReuse/ActiveRecord
          track_event(namespace_ids)
          all_diffs.each { |diff| log_changes(generate_diff_data(diff)) }
        end

        all_diffs
      end

      private

      def generate_diff_data(diff)
        {
          namespace_id: diff['namespace_id'],
          traversal_ids: diff['traversal_ids'],
          changes: {
            'total' => diff['total'],
            'info' => diff['info'],
            'unknown' => diff['unknown'],
            'low' => diff['low'],
            'medium' => diff['medium'],
            'high' => diff['high'],
            'critical' => diff['critical']
          }
        }
      end

      def log_changes(diff_data = {})
        log_data = diff_data.merge(
          class: self.class.name,
          message: 'Namespace vulnerability statistics adjusted'
        )
        Gitlab::AppLogger.warn(log_data)
      end

      def track_event(namespace_ids)
        track_internal_event(
          'activate_namespace_statistics_adjustment_service',
          feature_enabled_by_namespace_ids: namespace_ids
        )
      end

      def connection
        SecApplicationRecord.connection
      end

      def upsert_with_diffs_sql(namespace_data)
        format(UPSERT_WITH_DIFF_SQL,
          stats_sql: stats_sql(namespace_data),
          old_values_sql: old_values_sql,
          upsert_sql: upsert_sql,
          diff_sql: diff_sql)
      end

      def upsert_sql
        format(UPSERT_SQL, new_values: select_new_values_sql)
      end

      def select_new_values_sql
        SELECT_NEW_VALUES_SQL
      end

      def old_values_sql
        OLD_VALUES_SQL
      end

      def diff_sql
        NAMESPACE_DIFF_SQL
      end

      def stats_sql(namespace_data)
        format(STATS_SQL, with_values: namespace_data)
      end

      def non_zero_diffs(diffs)
        diffs.select do |diff|
          ::Enums::Vulnerability.severity_levels.keys.any? { |level| diff[level] != 0 }
        end
      end
    end
  end
end
