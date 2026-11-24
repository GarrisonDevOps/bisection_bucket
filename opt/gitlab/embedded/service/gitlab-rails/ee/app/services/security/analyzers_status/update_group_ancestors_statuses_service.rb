# frozen_string_literal: true

module Security
  module AnalyzersStatus
    class UpdateGroupAncestorsStatusesService < BaseUpdateAncestorsService
      def self.execute(group)
        new(group).execute
      end

      def diffs(traversal_ids, statuses_counters_coefficient = 1)
        # statuses_counters_coefficient is used to modify the diffs for later increase (1) or decrease (-1) operation
        return unless statuses_counters_coefficient.abs == 1

        diff = analyzer_statuses.each_with_object({}) do |analyzer_status, acc|
          acc[analyzer_status.analyzer_type.to_sym] = {
            "success" => statuses_counters_coefficient * analyzer_status.success,
            "failed" => statuses_counters_coefficient * analyzer_status.failure,
            "stale" => statuses_counters_coefficient * analyzer_status.stale
          }
        end

        {
          diff: diff,
          namespace_id: namespace.id,
          traversal_ids: traversal_ids || analyzer_statuses[0].traversal_ids
        }
      end

      def analyzer_statuses
        @analyzer_statuses ||= group_or_project.analyzer_group_statuses
      end

      def namespace
        group_or_project
      end
    end
  end
end
