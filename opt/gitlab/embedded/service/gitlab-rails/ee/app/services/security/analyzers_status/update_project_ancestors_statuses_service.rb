# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class UpdateProjectAncestorsStatusesService < BaseUpdateAncestorsService
      def self.execute(project)
        new(project).execute
      end

      def diffs(traversal_ids, statuses_counters_coefficient = 1)
        # statuses_counters_coefficient is used to modify the diffs for later increase (1) or decrease (-1) operation
        return unless statuses_counters_coefficient.abs == 1

        diff = analyzer_statuses
          .reject { |analyzer_status| analyzer_status.status == "not_configured" }
          .each_with_object({}) do |analyzer_status, acc|
          acc[analyzer_status.analyzer_type.to_sym] = {
            "success" => analyzer_status.status == "success" ? statuses_counters_coefficient : 0,
            "failed" => analyzer_status.status == "failed" ? statuses_counters_coefficient : 0,
            "stale" => analyzer_status.status == "stale" ? statuses_counters_coefficient : 0
          }
        end

        {
          diff: diff,
          namespace_id: namespace.id,
          traversal_ids: traversal_ids || analyzer_statuses[0].traversal_ids
        }
      end

      def namespace
        group_or_project.namespace
      end

      def analyzer_statuses
        @analyzer_statuses ||= group_or_project.analyzer_statuses
      end
    end
  end
end
