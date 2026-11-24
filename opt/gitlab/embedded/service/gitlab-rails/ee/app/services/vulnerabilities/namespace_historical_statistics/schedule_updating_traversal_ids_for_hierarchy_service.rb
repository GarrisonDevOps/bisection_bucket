# frozen_string_literal: true

module Vulnerabilities
  module NamespaceHistoricalStatistics
    class ScheduleUpdatingTraversalIdsForHierarchyService
      BATCH_SIZE = 100

      def self.execute(group)
        new(group).execute
      end

      def initialize(group)
        @group = group
      end

      def execute
        iterator.each_batch(of: BATCH_SIZE) do |group_ids|
          break unless group_ids.present?

          schedule_updating_traversal_ids_for_relevant_groups(group_ids)
        end
      end

      private

      attr_reader :group

      def iterator
        Gitlab::Database::NamespaceEachBatch.new(namespace_class: Group, cursor: start_cursor)
      end

      def start_cursor
        { current_id: group.id, depth: [group.id] }
      end

      def schedule_updating_traversal_ids_for_relevant_groups(group_ids)
        group_ids_with_statistics = find_group_ids_with_statistics(group_ids)

        return unless group_ids_with_statistics.present?

        schedule_updating_traversal_ids_for(group_ids_with_statistics)
      end

      # rubocop:disable CodeReuse/ActiveRecord -- Very specific use case
      # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- The query has a limit
      def find_group_ids_with_statistics(group_ids)
        values_list = Arel::Nodes::ValuesList.new(group_ids.zip).to_sql
        join_query = Vulnerabilities::NamespaceHistoricalStatistic.where('namespace_id = group_ids.id').to_sql
        from_clause = "(#{values_list}) AS group_ids(id), LATERAL(#{join_query}) AS join_query"

        Vulnerabilities::NamespaceHistoricalStatistic.from(from_clause).pluck('group_ids.id')
      end
      # rubocop:enable Database/AvoidUsingPluckWithoutLimit
      # rubocop:enable CodeReuse/ActiveRecord

      def schedule_updating_traversal_ids_for(group_ids)
        Vulnerabilities::NamespaceHistoricalStatistics::UpdateTraversalIdsWorker.bulk_perform_async_with_contexts(
          group_ids,
          arguments_proc: ->(group_id) { group_id },
          context_proc: ->(_) { { namespace: group } }
        )
      end
    end
  end
end
