# frozen_string_literal: true

module Vulnerabilities
  module Statistics
    class AdjustmentService
      TooManyProjectsError = Class.new(StandardError)

      UPSERT_SQL = <<~SQL
        INSERT INTO vulnerability_statistics
          (project_id, archived, traversal_ids, total, info, unknown, low, medium, high, critical, letter_grade, created_at, updated_at)
          (%{new_values})
        ON CONFLICT (project_id)
        DO UPDATE SET
          total = EXCLUDED.total,
          info = EXCLUDED.info,
          unknown = EXCLUDED.unknown,
          low = EXCLUDED.low,
          medium = EXCLUDED.medium,
          high = EXCLUDED.high,
          critical = EXCLUDED.critical,
          letter_grade = EXCLUDED.letter_grade,
          updated_at = EXCLUDED.updated_at
       RETURNING project_id
      SQL

      STATS_SQL = <<~SQL
        SELECT
          project_ids.project_id AS project_id,
          project_attributes.archived AS archived,
          project_attributes.traversal_ids AS traversal_ids,
          COALESCE(severity_counts.total, 0) AS total,
          COALESCE(severity_counts.info, 0) AS info,
          COALESCE(severity_counts.unknown, 0) AS unknown,
          COALESCE(severity_counts.low, 0) AS low,
          COALESCE(severity_counts.medium, 0) AS medium,
          COALESCE(severity_counts.high, 0) AS high,
          COALESCE(severity_counts.critical, 0) AS critical,
          (
            CASE
            WHEN severity_counts.critical > 0 THEN
              #{Statistic.letter_grades['f']}
            WHEN severity_counts.high > 0 OR severity_counts.unknown > 0 THEN
              #{Statistic.letter_grades['d']}
            WHEN severity_counts.medium > 0 THEN
              #{Statistic.letter_grades['c']}
            WHEN severity_counts.low > 0 THEN
              #{Statistic.letter_grades['b']}
            ELSE
              #{Statistic.letter_grades['a']}
            END
          ) AS letter_grade,
          now() AS created_at,
          now() AS updated_at
        FROM unnest(ARRAY[%{project_ids}]) project_ids(project_id)
        JOIN (%{project_attributes}) project_attributes(project_id, archived, traversal_ids)
          ON project_attributes.project_id = project_ids.project_id
        LEFT OUTER JOIN(
          SELECT
            vulnerability_reads.project_id AS project_id,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE severity = #{Vulnerability.severities['info']}) as info,
            COUNT(*) FILTER (WHERE severity = #{Vulnerability.severities['unknown']}) as unknown,
            COUNT(*) FILTER (WHERE severity = #{Vulnerability.severities['low']}) as low,
            COUNT(*) FILTER (WHERE severity = #{Vulnerability.severities['medium']}) as medium,
            COUNT(*) FILTER (WHERE severity = #{Vulnerability.severities['high']}) as high,
            COUNT(*) FILTER (WHERE severity = #{Vulnerability.severities['critical']}) as critical
          FROM vulnerability_reads
          WHERE
            vulnerability_reads.project_id IN (%{project_ids}) AND
            vulnerability_reads.state IN (%{active_states}) AND
            vulnerability_reads.resolved_on_default_branch = FALSE AND
            (vulnerability_reads.security_project_tracked_context_id IS NULL
              OR vulnerability_reads.security_project_tracked_context_id IN (%{default_branch_context_ids}))
          GROUP BY vulnerability_reads.project_id
        ) AS severity_counts ON severity_counts.project_id = project_ids.project_id
      SQL

      SELECT_NEW_VALUES_SQL = <<~SQL
        SELECT project_id, archived, traversal_ids, total, info, unknown, low, medium, high, critical, letter_grade, created_at, updated_at
        FROM new_values
      SQL

      OLD_VALUES_SQL = <<~SQL
        SELECT
          project_id,
          traversal_ids,
          total,
          critical,
          high,
          medium,
          low,
          unknown,
          info
        FROM vulnerability_statistics
        WHERE project_id IN (SELECT project_id FROM new_values)
      SQL

      NAMESPACE_DIFF_SQL = <<~SQL
          SELECT
              new_values.traversal_ids[array_length(new_values.traversal_ids, 1)] AS namespace_id,
              new_values.traversal_ids,
              ARRAY_AGG(DISTINCT new_values.project_id ORDER BY new_values.project_id) AS affected_project_ids,
              SUM(new_values.total - COALESCE(old_values.total, 0)) AS total,
              SUM(new_values.info - COALESCE(old_values.info, 0)) AS info,
              SUM(new_values.unknown - COALESCE(old_values.unknown, 0)) AS unknown,
              SUM(new_values.low - COALESCE(old_values.low, 0)) AS low,
              SUM(new_values.medium - COALESCE(old_values.medium, 0)) AS medium,
              SUM(new_values.high - COALESCE(old_values.high, 0)) AS high,
              SUM(new_values.critical - COALESCE(old_values.critical, 0)) AS critical
          FROM new_values
          LEFT JOIN old_values
              ON new_values.project_id = old_values.project_id
          WHERE EXISTS (
              SELECT 1
              FROM upserted
              WHERE upserted.project_id = new_values.project_id
          )
          AND (
              new_values.total != COALESCE(old_values.total, 0) OR
              new_values.info != COALESCE(old_values.info, 0) OR
              new_values.unknown != COALESCE(old_values.unknown, 0) OR
              new_values.low != COALESCE(old_values.low, 0) OR
              new_values.medium != COALESCE(old_values.medium, 0) OR
              new_values.high != COALESCE(old_values.high, 0) OR
              new_values.critical != COALESCE(old_values.critical, 0)
          )
          GROUP BY namespace_id, new_values.traversal_ids
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
      SQL

      MAX_PROJECTS = 1_000

      def self.execute(project_ids)
        new(project_ids).execute
      end

      def initialize(project_ids)
        raise TooManyProjectsError, "Cannot adjust statistics for more than #{MAX_PROJECTS} projects" if project_ids.size > MAX_PROJECTS

        self.project_ids = project_ids
      end

      def execute
        filter_project_ids
        return { diff: [], affected_project_ids: [] } if project_ids.blank?

        diffs_with_affected_project = connection.execute(upsert_with_diffs_sql)
        organize_diff_results(diffs_with_affected_project)
      end

      private

      attr_accessor :project_ids

      delegate :connection, to: Statistic, private: true

      def filter_project_ids
        self.project_ids = Project.id_in(project_ids).pluck_primary_key
      end

      def upsert_with_diffs_sql
        UPSERT_WITH_DIFF_SQL % {
          stats_sql: stats_sql,
          old_values_sql: old_values_sql,
          upsert_sql: upsert_sql,
          diff_sql: diff_sql
        }
      end

      def diff_sql
        NAMESPACE_DIFF_SQL
      end

      def upsert_sql
        UPSERT_SQL % { new_values: select_new_values_sql }
      end

      def old_values_sql
        OLD_VALUES_SQL
      end

      def select_new_values_sql
        SELECT_NEW_VALUES_SQL
      end

      def stats_sql
        STATS_SQL % {
          project_ids: project_ids.join(', '),
          project_attributes: project_attributes_as_values_sql,
          active_states: active_states,
          default_branch_context_ids: default_branch_context_ids_sql
        }
      end

      def project_attributes_as_values_sql
        # rubocop:disable CodeReuse/ActiveRecord -- not reusable
        attributes = Project.id_in(project_ids).joins_namespace.limit(project_ids.length)
          .pluck(:id, :archived, :traversal_ids, :namespace_id)
        # rubocop:enable CodeReuse/ActiveRecord

        tuples = attributes.map do |row|
          [
            row[0],
            row[1],
            Arel.sql("ARRAY#{row[2]}::bigint[]")
          ]
        end

        Arel::Nodes::ValuesList.new(tuples).to_sql
      end

      def active_states
        Vulnerability.active_state_values.join(', ')
      end

      # Returns a SQL-safe comma-separated list of tracked context IDs
      # corresponding to each project's actual default branch.
      # This avoids relying on the `is_default` column, which may have
      # duplicate entries until the cleanup BBM is finalized.
      def default_branch_context_ids_sql
        ids = default_branch_context_ids
        ids.empty? ? 'NULL' : ids.join(', ')
      end

      def default_branch_context_ids
        projects = Project.id_in(project_ids)

        Security::ProjectTrackedContext.default_branch_contexts_by_project_id(projects).values.map(&:id)
      end

      def parse_postgres_array(array_string)
        array_string.gsub(/[{}]/, '').split(',').map(&:to_i)
      end

      def organize_diff_results(diffs_with_affected_project)
        cleaned_diffs = diffs_with_affected_project.map { |diff| diff.except('affected_project_ids') }
        affected_project_ids = diffs_with_affected_project.flat_map do |diff|
          parse_postgres_array(diff['affected_project_ids'])
        end.uniq

        { diff: cleaned_diffs, affected_project_ids: affected_project_ids }
      end
    end
  end
end
