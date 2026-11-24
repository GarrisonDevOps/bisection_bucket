# frozen_string_literal: true

module Vulnerabilities
  module NamespaceHistoricalStatistics
    class AdjustmentService
      TooManyProjectsError = Class.new(StandardError)

      NEW_INDEX_NAME = 'idx_vuln_ns_hist_stats_on_traversal_ids_date_and_ns_id'
      OLD_CONFLICT_COLUMNS = '(traversal_ids, date)'
      NEW_CONFLICT_COLUMNS = '(traversal_ids, date, namespace_id)'

      UPSERT_SQL = <<~SQL
        INSERT INTO vulnerability_namespace_historical_statistics
          (total, info, unknown, low, medium, high, critical, letter_grade, traversal_ids, namespace_id, date, created_at, updated_at)
          (%{stats_sql})
        ON CONFLICT %{conflict_target}
        DO UPDATE SET
          total = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.total
            ELSE vulnerability_namespace_historical_statistics.total + EXCLUDED.total
            END,
          info = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.info
            ELSE vulnerability_namespace_historical_statistics.info + EXCLUDED.info
            END,
          unknown = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.unknown
            ELSE vulnerability_namespace_historical_statistics.unknown + EXCLUDED.unknown
            END,
          low = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.low
            ELSE vulnerability_namespace_historical_statistics.low + EXCLUDED.low
            END,
          medium = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.medium
            ELSE vulnerability_namespace_historical_statistics.medium + EXCLUDED.medium
            END,
          high = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.high
            ELSE vulnerability_namespace_historical_statistics.high + EXCLUDED.high
            END,
          critical = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.critical
            ELSE vulnerability_namespace_historical_statistics.critical + EXCLUDED.critical
            END,
          letter_grade = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.letter_grade
            ELSE GREATEST(vulnerability_namespace_historical_statistics.letter_grade, EXCLUDED.letter_grade)
            END,
          updated_at = CASE WHEN vulnerability_namespace_historical_statistics.migrating
            THEN vulnerability_namespace_historical_statistics.updated_at
            ELSE EXCLUDED.updated_at
            END
      SQL

      STATS_SQL = <<~SQL
        WITH project_to_namespace_traversal_ids (project_id, namespace_id) AS (
            %{with_values}
        )
        SELECT
          SUM(total) AS total,
          SUM(info) AS info,
          SUM(unknown) AS unknown,
          SUM(low) AS low,
          SUM(medium) AS medium,
          SUM(high) AS high,
          SUM(critical) AS critical,
          MAX(letter_grade) AS letter_grade,
          traversal_ids as traversal_ids,
          project_to_namespace_traversal_ids.namespace_id as namespace_id,
          vulnerability_statistics.updated_at::date AS date,
          now() AS created_at,
          now() AS updated_at
        FROM vulnerability_statistics
        INNER JOIN project_to_namespace_traversal_ids ON
          project_to_namespace_traversal_ids.project_id = vulnerability_statistics.project_id
        WHERE vulnerability_statistics.project_id IN (%{project_ids})
        GROUP BY traversal_ids, namespace_id, date
      SQL

      MAX_PROJECTS = 1_000

      def self.execute(project_ids)
        new(project_ids).execute
      end

      def initialize(project_ids)
        if project_ids.size > MAX_PROJECTS
          raise TooManyProjectsError, "Cannot adjust namespace statistics for more than #{MAX_PROJECTS} projects"
        end

        @project_ids = project_ids
      end

      def execute
        return if @project_ids.empty?

        project_ids.each_slice(100) do |project_ids_batch|
          with_project_info = with_values(project_ids_batch)
          next if with_project_info.blank?

          joined_project_ids = project_ids_batch.map { |id| Integer(id) }.join(', ')

          SecApplicationRecord.connection.execute(upsert_sql(joined_project_ids, with_project_info))
        end
      end

      private

      attr_reader :project_ids

      def upsert_sql(project_ids_batch, with_project_information)
        format(UPSERT_SQL,
          stats_sql: stats_sql(project_ids_batch, with_project_information),
          conflict_target: conflict_target)
      end

      def conflict_target
        if new_index_available?
          NEW_CONFLICT_COLUMNS
        else
          OLD_CONFLICT_COLUMNS
        end
      end

      def new_index_available?
        SecApplicationRecord.connection.index_exists?(
          :vulnerability_namespace_historical_statistics,
          %i[traversal_ids date namespace_id],
          name: NEW_INDEX_NAME
        )
      end

      def stats_sql(project_ids_batch, with_project_information)
        format(STATS_SQL, project_ids: project_ids_batch, with_values: with_project_information)
      end

      def with_values(project_ids_batch)
        # Because the project information is stored in the main database
        # and the vulnerability_namespace_historical_statistics table is stored in the sec database,
        # We fetch the needed project information beforehand and enter those values as a `with` statement in the query
        project_info = ProjectSetting.for_projects(project_ids_batch).with_namespace
                                     .has_vulnerabilities.limit(project_ids_batch.length)
                                     # rubocop:disable CodeReuse/ActiveRecord -- Plucking these attributes in this order is very specific to this service.
                                     .pluck(:project_id, :namespace_id)
        # rubocop:enable CodeReuse/ActiveRecord

        return if project_info.blank?

        values = project_info.map do |row|
          [
            row[0],
            row[1]
          ]
        end

        Arel::Nodes::ValuesList.new(values).to_sql
      end
    end
  end
end
