# frozen_string_literal: true

module Security
  module AnalyzerNamespaceStatuses
    class FindNamespacesWithAnalyzerStatusesService
      include Security::NamespaceTraversalSqlBuilder

      NAMESPACES_WITH_ANALYZER_STATUSES_SQL = <<~SQL
        WITH namespace_data (id, traversal_ids, next_traversal_ids) AS (
          %{with_values}
        )
        SELECT
          namespace_data.id
        FROM
          namespace_data,
          LATERAL (
            SELECT
              1
            FROM
              analyzer_project_statuses
            WHERE
              analyzer_project_statuses.archived = false
              AND analyzer_project_statuses.traversal_ids >= namespace_data.traversal_ids
              AND analyzer_project_statuses.traversal_ids < namespace_data.next_traversal_ids
            LIMIT 1
          ) does_exist
      SQL

      def self.execute(namespace_values)
        new(namespace_values).execute
      end

      def initialize(namespace_values)
        @namespace_values = namespace_values
      end

      def execute
        return [] unless namespace_values.present?

        namespace_ids_with_analyzer_statuses.values.flatten
      end

      private

      attr_reader :namespace_values

      def namespace_ids_with_analyzer_statuses
        Security::AnalyzerProjectStatus.connection.execute(namespaces_with_analyzer_statuses_sql)
      end

      def namespaces_with_analyzer_statuses_sql
        format(NAMESPACES_WITH_ANALYZER_STATUSES_SQL,
          with_values: namespaces_and_traversal_ids_query_values(namespace_values))
      end
    end
  end
end
