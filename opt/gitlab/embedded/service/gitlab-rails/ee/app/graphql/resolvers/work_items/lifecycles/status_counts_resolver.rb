# frozen_string_literal: true

module Resolvers
  module WorkItems
    module Lifecycles
      class StatusCountsResolver < Resolvers::WorkItems::BaseResolver
        MAX_COUNTABLE_WORK_ITEMS = 999

        type [Types::WorkItems::StatusCountType], null: true

        alias_method :lifecycle, :object

        def resolve
          return unless work_item_status_licensed_feature_available?

          status_counts
        end

        private

        def namespace
          context[:namespace]
        end
        strong_memoize_attr :namespace

        def root_ancestor
          namespace&.root_ancestor
        end

        def status_counts
          lifecycle.ordered_statuses.map do |status|
            { status: status, count: count_work_items_for_status(status) }
          end
        end

        def count_work_items_for_status(status)
          work_item_types = lifecycle.work_item_types(namespace).map(&:base_type)
          return if work_item_types.blank?

          finder = ::WorkItems::WorkItemsFinder.new(
            current_user,
            {
              group_id: namespace.id,
              include_descendants: true,
              issue_types: work_item_types,
              status: { name: status.name },
              state: 'all'
            }
          )

          relation = finder.execute

          # For performance reasons, we don't count exact numbers above MAX_COUNTABLE_WORK_ITEMS
          count = relation.page.total_count_with_limit(:all, limit: MAX_COUNTABLE_WORK_ITEMS + 1)
          count > MAX_COUNTABLE_WORK_ITEMS ? "#{MAX_COUNTABLE_WORK_ITEMS}+" : count.to_s
        end
      end
    end
  end
end
