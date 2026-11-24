# frozen_string_literal: true

module EE
  module Types
    module WorkItems
      module Widgets
        module LinkedItemsType
          extend ActiveSupport::Concern
          include ::Gitlab::Utils::StrongMemoize

          prepended do
            field :blocked, GraphQL::Types::Boolean, null: true,
              description: 'Indicates the work item is blocked.'

            field :blocking_count, GraphQL::Types::Int, null: true,
              description: 'Count of items the work item is blocking.'

            field :blocked_by_count, GraphQL::Types::Int, null: true,
              description: 'Count of items blocking the work item.'

            def blocked
              aggregator_class.new(context, object.work_item.id) { |count| (count || 0) > 0 }
            end

            def blocked_by_count
              aggregator_class.new(context, object.work_item.id) { |count| count || 0 }
            end

            def blocking_count
              object.work_item.blocking_issues_count
            end

            private

            def aggregator_class
              ::Gitlab::Graphql::Aggregations::WorkItems::LazyLinksAggregate
            end
          end
        end
      end
    end
  end
end
