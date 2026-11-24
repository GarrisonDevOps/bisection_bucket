# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class UpdateService
      # This expands the traversal ids.
      # for example, This row:
      # {"namespace_id": 3, "traversal_ids": {1, 2, 3}, "total": 1, ...}
      # will be transformed into three lines:
      # {"namespace_id": 1, "traversal_ids": {1}, "total": 1, ...}
      # {"namespace_id": 2, "traversal_ids": {1, 2}, "total": 1, ...}
      # {"namespace_id": 3, "traversal_ids": {1, 2, 3}, "total": 1, ...}
      EXPANDED_PATHS_SQL = <<~SQL
        SELECT
          -- For each position in the array, select all elements up to that position
          d.traversal_ids[i] AS namespace_id,
          d.traversal_ids[1:i] AS traversal_ids,
          d.total,
          d.critical,
          d.high,
          d.medium,
          d.low,
          d.unknown,
          d.info
        FROM
          diffs d,
          generate_series(1, array_length(d.traversal_ids, 1)) AS i
      SQL

      # This service receives diffs with unique namespaces.
      # However, the expansion of the traversal_ids might cause namespace_id duplicates.
      # In those cases, we will sum up the diffs.
      # For example: two input rows:
      # {"namespace_id": 2, "traversal_ids": {1, 2}, "total": 1, "critical": 1, "high": 0, ...}
      # {"namespace_id": 3, "traversal_ids": {1, 3}, "total": 1, "critical": 0, "high": 1, ...}
      # the expansion will create four rows:
      # {"namespace_id": 1, "traversal_ids": {1}, "total": 1, "critical": 1, "high": 0, ...}
      # {"namespace_id": 2, "traversal_ids": {1, 2}, "total": 1, "critical": 1, "high": 0, ...}
      # {"namespace_id": 1, "traversal_ids": {1}, "total": 1, "critical": 0, "high": 1, ...}
      # {"namespace_id": 3, "traversal_ids": {1, 3}, "total": 1, "critical": 0, "high": 1, ...}
      # So we need to aggregate the diffs for namespace 1
      AGGREGATED_PATHS_SQL = <<~SQL
        SELECT
          namespace_id,
          traversal_ids,
          SUM(total) AS total,
          SUM(critical) AS critical,
          SUM(high) AS high,
          SUM(medium) AS medium,
          SUM(low) AS low,
          SUM(unknown) AS unknown,
          SUM(info) AS info
        FROM expanded_paths
        GROUP BY namespace_id, traversal_ids
        ORDER BY namespace_id, traversal_ids
      SQL

      UPSERT_SQL = <<~SQL
        WITH diffs(namespace_id, traversal_ids, total, critical, high, medium, low, unknown, info) AS (
          %{diffs_input}
        ), expanded_paths AS (
          %{expanded_paths_sql}
        ), aggregated_paths AS (
          %{aggregated_paths_sql}
        )

        INSERT INTO vulnerability_namespace_statistics AS vt (
          namespace_id, traversal_ids, total, critical, high, medium, low, unknown, info, created_at, updated_at
        )
        SELECT
          ap.namespace_id,
          ap.traversal_ids,
          ap.total,
          ap.critical,
          ap.high,
          ap.medium,
          ap.low,
          ap.unknown,
          ap.info,
          now(),
          now()
        FROM aggregated_paths ap
        ORDER BY ap.namespace_id
        ON CONFLICT (namespace_id)
        DO UPDATE SET
          traversal_ids = excluded.traversal_ids,
          total = GREATEST(vt.total + excluded.total, 0),
          critical = GREATEST(vt.critical + excluded.critical, 0),
          high = GREATEST(vt.high + excluded.high, 0),
          medium = GREATEST(vt.medium + excluded.medium, 0),
          low = GREATEST(vt.low + excluded.low, 0),
          unknown = GREATEST(vt.unknown + excluded.unknown, 0),
          info = GREATEST(vt.info + excluded.info, 0),
          updated_at = excluded.updated_at
      SQL

      def self.execute(diffs)
        new(diffs).execute
      end

      def initialize(diffs)
        @diffs = diffs
      end

      def execute
        return if diffs.nil?

        filtered_diffs = filter_diffs(diffs)
        return unless filtered_diffs.any?

        @diffs = filtered_diffs
        update_statistics_based_on_diff
      end

      private

      attr_reader :diffs

      delegate :connection, to: Statistic, private: true

      def filter_diffs(diffs)
        diffs = diffs.reject { |item| item.nil? || (item.is_a?(Hash) && item.empty?) }
        diffs.reject { |item| item['namespace_id'].nil? || item['traversal_ids'].nil? }
      end

      def update_statistics_based_on_diff
        connection.execute(upsert_sql)
      end

      def upsert_sql
        format(
          UPSERT_SQL,
          diffs_input: diffs_input_values,
          expanded_paths_sql: EXPANDED_PATHS_SQL,
          aggregated_paths_sql: AGGREGATED_PATHS_SQL
        )
      end

      def diffs_input_values
        values = diffs.map do |diff|
          [
            diff["namespace_id"],
            Arel.sql("'#{diff['traversal_ids']}'::bigint[]"),
            diff.fetch("total", 0),
            diff.fetch("critical", 0),
            diff.fetch("high", 0),
            diff.fetch("medium", 0),
            diff.fetch("low", 0),
            diff.fetch("unknown", 0),
            diff.fetch("info", 0)
          ]
        end

        Arel::Nodes::ValuesList.new(values).to_sql
      end
    end
  end
end
