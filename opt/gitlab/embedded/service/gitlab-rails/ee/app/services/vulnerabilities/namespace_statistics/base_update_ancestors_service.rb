# frozen_string_literal: true

module Vulnerabilities
  module NamespaceStatistics
    class BaseUpdateAncestorsService
      def initialize(vulnerable)
        @vulnerable = vulnerable
      end

      def execute
        return unless previous_traversal_ids.present? && (previous_traversal_ids != vulnerable_namespace.traversal_ids)

        Vulnerabilities::NamespaceStatistic.transaction do
          reduce_from_old_ancestors
          add_to_new_ancestors
        end
      end

      private

      attr_reader :vulnerable

      def reduce_from_old_ancestors
        reduce_diff = diff(vulnerable_statistics, previous_traversal_ids, -1)
        UpdateService.execute([reduce_diff])
      end

      def add_to_new_ancestors
        increase_diff = diff(vulnerable_statistics, vulnerable_namespace.traversal_ids)
        UpdateService.execute([increase_diff])
      end

      def previous_traversal_ids
        @previous_traversal_ids ||= vulnerable_statistics&.traversal_ids
      end

      def diff(statistics, traversal_ids, statistics_coefficient = 1)
        {
          "namespace_id" => vulnerable_namespace.id,
          "traversal_ids" => format_traversal_ids(traversal_ids),
          "total" => statistics_coefficient * statistics.total,
          "critical" => statistics_coefficient * statistics.critical,
          "high" => statistics_coefficient * statistics.high,
          "medium" => statistics_coefficient * statistics.medium,
          "low" => statistics_coefficient * statistics.low,
          "info" => statistics_coefficient * statistics.info,
          "unknown" => statistics_coefficient * statistics.unknown
        }
      end

      def format_traversal_ids(traversal_ids)
        "{#{traversal_ids.join(',')}}"
      end

      def vulnerable_namespace
        raise NotImplementedError
      end

      def vulnerable_statistics
        raise NotImplementedError
      end
    end
  end
end
