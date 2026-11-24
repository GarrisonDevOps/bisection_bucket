# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class FindVulnerableNamespacesService
      include Security::NamespaceTraversalSqlBuilder

      NAMESPACES_WITH_VULNERABILITIES_SQL = <<~SQL
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
              vulnerability_statistics
            WHERE
              vulnerability_statistics.archived = false
              AND vulnerability_statistics.traversal_ids >= namespace_data.traversal_ids
              AND vulnerability_statistics.traversal_ids < namespace_data.next_traversal_ids
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

        namespace_ids_with_vulnerabilities.values.flatten
      end

      private

      attr_reader :namespace_values

      def namespace_ids_with_vulnerabilities
        Vulnerabilities::Statistic.connection.execute(namespaces_with_vulnerabilities_sql)
      end

      def namespaces_with_vulnerabilities_sql
        format(NAMESPACES_WITH_VULNERABILITIES_SQL,
          with_values: namespaces_and_traversal_ids_query_values(namespace_values))
      end
    end
  end
end
