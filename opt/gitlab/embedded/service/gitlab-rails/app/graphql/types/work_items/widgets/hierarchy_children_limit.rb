# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      module HierarchyChildrenLimit
        CHILDREN_IDS_DESCRIPTION = 'Global IDs of child work items ' \
          "(maximum is #{::Types::BaseArgument::MAX_ARRAY_SIZE}). " \
          'When the `work_item_hierarchy_add_children_limits` feature flag is enabled, a request can add at most ' \
          "#{::WorkItems::Callbacks::Hierarchy::MAX_CHILDREN_PER_REQUEST} child items.".freeze

        # Shared `prepare:` for `childrenIds` arguments. Runs before `loads:`, so the cap is
        # enforced before every child is fetched.
        CHILDREN_IDS_PREPARE = ->(ids, ctx) do
          if ::WorkItems::Callbacks::Hierarchy.children_limit_exceeded?(ids, ctx[:current_user])
            raise Gitlab::Graphql::Errors::ArgumentError, ::WorkItems::Callbacks::Hierarchy.children_limit_error_message
          end

          ids
        end
      end
    end
  end
end
