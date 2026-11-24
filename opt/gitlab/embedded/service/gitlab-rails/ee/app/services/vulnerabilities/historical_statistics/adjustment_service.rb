# frozen_string_literal: true

module Vulnerabilities
  module HistoricalStatistics
    class AdjustmentService
      TooManyProjectsError = Class.new(StandardError)

      UPSERT_SQL = <<~SQL
        INSERT INTO vulnerability_historical_statistics
          (project_id, total, info, unknown, low, medium, high, critical, letter_grade, date, created_at, updated_at)
          (%{stats_sql})
        ON CONFLICT (project_id, date)
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
        RETURNING
          project_id, created_at, updated_at

      SQL

      STATS_SQL = <<~SQL
        WITH current_time_now AS (
          SELECT now() AS current_timestamp
        )
        SELECT
          project_id,
          total,
          info,
          unknown,
          low,
          medium,
          high,
          critical,
          letter_grade,
          updated_at AS date,
          current_timestamp AS created_at,
          current_timestamp AS updated_at
        FROM vulnerability_statistics, current_time_now
        WHERE project_id IN (%{project_ids})
      SQL

      MAX_PROJECTS = 1_000

      def self.execute(project_ids)
        new(project_ids).execute
      end

      def initialize(project_ids)
        raise TooManyProjectsError, "Cannot adjust statistics for more than #{MAX_PROJECTS} projects" if project_ids.size > MAX_PROJECTS

        @project_ids = project_ids.map { |id| Integer(id) }.join(', ')
      end

      def execute
        project_ids_with_timestamps_metadata = Vulnerabilities::HistoricalStatistic.connection.execute(upsert_sql)
        filter_inserted_project_ids(project_ids_with_timestamps_metadata)
      end

      private

      attr_reader :project_ids

      def upsert_sql
        UPSERT_SQL % { stats_sql: stats_sql }
      end

      def stats_sql
        STATS_SQL % { project_ids: project_ids }
      end

      def filter_inserted_project_ids(project_ids_with_timestamps_metadata)
        project_ids_with_timestamps_metadata.filter_map do |project_id_with_timestamps|
          # Choose only the newly inserted entries to ensure that each project is counted only once
          project_id_with_timestamps['project_id'] if project_id_with_timestamps['created_at'] == project_id_with_timestamps['updated_at']
        end
      end
    end
  end
end
