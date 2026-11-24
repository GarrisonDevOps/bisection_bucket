# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class DiffsService
      def initialize(projects_analyzer_statuses)
        @projects_analyzer_statuses = projects_analyzer_statuses
        @namespace_diffs = {}
      end

      def execute
        return unless projects_analyzer_statuses.present?

        projects_analyzer_statuses.each do |project, analyzer_statuses|
          process_project_diff(project, analyzer_statuses)
        end

        namespace_diffs.values if namespace_diffs.present?
      end

      private

      attr_reader :projects_analyzer_statuses, :namespace_diffs

      def process_project_diff(project, analyzer_statuses)
        return unless analyzer_statuses.present?

        project_diff_result = DiffService.new(project, analyzer_statuses).execute
        aggregate_namespace_diffs(project_diff_result) if project_diff_result.present?
      end

      def aggregate_namespace_diffs(project_diff_result)
        return unless project_diff_result[:diff].present?

        namespace_id = project_diff_result[:namespace_id]

        namespace_diffs[namespace_id] ||= {
          namespace_id: namespace_id,
          traversal_ids: project_diff_result[:traversal_ids],
          diff: {}
        }

        project_diff_result[:diff].each do |analyzer_type, status_changes|
          namespace_diffs[namespace_id][:diff][analyzer_type] ||= {}

          status_changes.each do |status, count|
            namespace_diffs[namespace_id][:diff][analyzer_type][status] ||= 0
            namespace_diffs[namespace_id][:diff][analyzer_type][status] += count
          end
        end
      end
    end
  end
end
