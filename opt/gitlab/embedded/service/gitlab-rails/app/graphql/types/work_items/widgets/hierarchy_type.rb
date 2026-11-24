# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      # Disabling widget level authorization as it might be too granular
      # and we already authorize the parent work item
      # rubocop:disable Graphql/AuthorizeTypes
      class HierarchyType < BaseObject
        graphql_name 'WorkItemWidgetHierarchy'
        description 'Represents a hierarchy widget'

        authorize_granular_token skip_reason: :parent_authorizes

        implements ::Types::WorkItems::WidgetInterface

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :parent, ::Types::WorkItemType,
          null: true, complexity: 5, scopes: [:api, :read_api, :ai_workflows],
          description: 'Parent work item.'

        field :children, ::Types::WorkItemType.connection_type,
          null: true, complexity: 5, scopes: [:api, :read_api, :ai_workflows],
          description: 'Child work items.',
          resolver: Resolvers::WorkItems::ChildrenResolver

        field :ancestors, ::Types::WorkItemType.connection_type,
          null: true, complexity: 5, scopes: [:api, :read_api, :ai_workflows],
          description: 'Ancestors (parents) of the work item.',
          extras: [:lookahead],
          resolver: Resolvers::WorkItems::AncestorsResolver

        field :has_children, GraphQL::Types::Boolean,
          null: false, complexity: 1,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Indicates if the work item has children.'

        field :has_parent, GraphQL::Types::Boolean,
          null: false, complexity: 1, method: :has_parent?,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Indicates if the work item has a parent.'

        field :rolled_up_counts_by_type, [::Types::WorkItems::WorkItemTypeCountsByStateType],
          null: false, description: 'Counts of descendant work items by work item type and state.',
          experiment: { milestone: '17.3' }

        field :depth_limit_reached_by_type, [::Types::WorkItems::WorkItemTypeDepthLimitReachedByType],
          null: false, description: 'Depth limit reached by allowed work item type.',
          experiment: { milestone: '17.4' }

        def has_children?
          BatchLoader::GraphQL.for(object.work_item.id).batch(default_value: false) do |ids, loader|
            ::WorkItems::ParentLink.parent_ids_with_children(ids).each { |id| loader.call(id, true) }
          end
        end

        alias_method :has_children, :has_children?

        def rolled_up_counts_by_type
          return object.rolled_up_counts_by_type unless object.batch_rolled_up_counts?

          lazy_counts = BatchLoader::GraphQL.for(object.work_item.id).batch(default_value: {}) do |ids, loader|
            ::WorkItems::ParentLink.descendant_counts_by_type_and_state(ids).each do |id, counts|
              loader.call(id, counts)
            end
          end

          Gitlab::Graphql::Lazy.with_value(lazy_counts) { |counts| object.rolled_up_counts_by_type(counts) }
        end
      end
      # rubocop:enable Graphql/AuthorizeTypes
    end
  end
end
