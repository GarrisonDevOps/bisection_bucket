# frozen_string_literal: true

module Security
  module AnalyzerNamespaceStatuses
    class AdjustmentService
      include Security::NamespaceTraversalSqlBuilder

      TooManyNamespacesError = Class.new(StandardError)

      UPSERT_SQL = <<~SQL
        INSERT INTO analyzer_namespace_statuses
          (analyzer_type, success, failure, stale, traversal_ids, namespace_id, created_at, updated_at)
          (%{new_values})
        ON CONFLICT (namespace_id, analyzer_type)
        DO UPDATE SET
          success = EXCLUDED.success,
          failure = EXCLUDED.failure,
          stale = EXCLUDED.stale,
          updated_at = EXCLUDED.updated_at,
          traversal_ids = EXCLUDED.traversal_ids
        RETURNING namespace_id
      SQL

      STATS_SQL = <<~SQL
        WITH namespace_data (namespace_id, traversal_ids, next_traversal_id) AS (
            %{with_values}
        ),
        project_stats AS (
          SELECT
            analyzer_project_statuses.analyzer_type,
            COALESCE(SUM((status = 1)::int), 0) AS success,
            COALESCE(SUM((status = 2)::int), 0) AS failure,
            COALESCE(SUM((status = 3)::int), 0) AS stale,
            namespace_data.traversal_ids,
            namespace_data.namespace_id,
            now() AS created_at,
            now() AS updated_at
          FROM namespace_data
          LEFT JOIN analyzer_project_statuses
            ON analyzer_project_statuses.archived = FALSE
            AND analyzer_project_statuses.traversal_ids >= namespace_data.traversal_ids
            AND analyzer_project_statuses.traversal_ids < namespace_data.next_traversal_id
          GROUP BY namespace_data.traversal_ids, namespace_data.namespace_id, analyzer_project_statuses.analyzer_type
          HAVING count(analyzer_project_statuses.analyzer_type) > 0
        ),
        existing_analyzer_types AS (
          SELECT DISTINCT
            analyzer_namespace_statuses.analyzer_type,
            namespace_data.traversal_ids,
            namespace_data.namespace_id,
            now() AS created_at,
            now() AS updated_at
          FROM namespace_data
          INNER JOIN analyzer_namespace_statuses
            ON analyzer_namespace_statuses.namespace_id = namespace_data.namespace_id
          WHERE NOT EXISTS (
            SELECT 1 FROM project_stats
            WHERE project_stats.namespace_id = namespace_data.namespace_id
            AND project_stats.analyzer_type = analyzer_namespace_statuses.analyzer_type
          )
        )
        SELECT analyzer_type, success, failure, stale, traversal_ids, namespace_id, created_at, updated_at
        FROM project_stats

        UNION ALL

        SELECT analyzer_type, 0 AS success, 0 AS failure, 0 AS stale, traversal_ids, namespace_id, created_at, updated_at
        FROM existing_analyzer_types
      SQL

      SELECT_NEW_VALUES_SQL = <<~SQL
        SELECT analyzer_type, success, failure, stale, traversal_ids, namespace_id, created_at, updated_at
        FROM new_values
      SQL

      OLD_VALUES_SQL = <<~SQL
        SELECT
          namespace_id,
          traversal_ids,
          analyzer_type,
          success,
          failure,
          stale
        FROM analyzer_namespace_statuses
        WHERE namespace_id IN (SELECT namespace_id FROM new_values)
      SQL

      NAMESPACE_DIFF_SQL = <<~SQL
        SELECT
          new_values.namespace_id AS namespace_id,
          new_values.traversal_ids,
          new_values.analyzer_type,
          new_values.success - COALESCE(old_values.success, 0) AS success,
          new_values.failure - COALESCE(old_values.failure, 0) AS failure,
          new_values.stale - COALESCE(old_values.stale, 0) AS stale
        FROM new_values
        LEFT JOIN old_values
          ON new_values.namespace_id = old_values.namespace_id AND
             new_values.analyzer_type = old_values.analyzer_type
        WHERE EXISTS (
          SELECT 1
          FROM upserted
          WHERE upserted.namespace_id = new_values.namespace_id
        )
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
          success != 0 OR
          failure != 0 OR
          stale != 0
      SQL

      MAX_NAMESPACES = 1_000
      BATCH_SIZE = 100

      def self.execute(namespace_ids)
        new(namespace_ids).execute
      end

      def initialize(namespace_ids)
        if namespace_ids.size > MAX_NAMESPACES
          raise TooManyNamespacesError,
            "Cannot adjust analyzer namespace statuses for more than #{MAX_NAMESPACES} namespaces"
        end

        @namespace_ids = namespace_ids
      end

      def execute
        all_diffs = []
        return all_diffs if @namespace_ids.empty?

        @namespace_ids.each_slice(BATCH_SIZE) do |namespace_ids_batch|
          namespace_data = with_namespace_data(namespace_ids_batch)
          next if namespace_data.blank?

          diffs = connection.execute(upsert_with_diffs_sql(namespace_data))
          all_diffs.concat(non_zero_diffs(diffs.to_a))
        end

        all_diffs
      end

      private

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
          [diff["success"], diff["failure"], diff["stale"]].any? { |count| count != 0 }
        end
      end
    end
  end
end
