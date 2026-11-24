# frozen_string_literal: true

module Ai
  module Catalog
    # Finds AI catalog items for a specific project
    #
    # Arguments:
    #   current_user - User performing the search (required for feature flag and permission checks)
    #   project - Project to find AI catalog items for
    #   params - Hash containing search parameters:
    #     :all_available - Boolean, when true includes public items from the project's organization
    #     :item_types - Array of item types to filter by. E.g.: ['agent', 'flow']
    #     :enabled - Boolean, filters items by their enabled state in the project:
    #                - true: returns only enabled items
    #                - false: returns only disabled items
    #                - nil/blank: returns all items regardless of enabled state
    #     :search - String to search for in item name and description
    #
    # Returns ActiveRecord::Relation
    class ProjectItemsFinder < BaseContainerItemsFinder
      private

      alias_method :project, :container

      def authorized?
        Ability.allowed?(current_user, :read_ai_catalog_item, project)
      end

      def init_collection
        items = Item.not_deleted.for_project(project)

        return items unless params[:all_available]

        items.or(available_items)
      end

      def filter_items(items)
        by_enabled_state(items)
      end

      def by_enabled_state(items)
        return items if params[:enabled].nil?

        enabled_items = project.configured_ai_catalog_items.by_enabled(true)

        if params[:enabled]
          items.id_in(enabled_items.select(:ai_catalog_item_id))
        else
          items.id_not_in(enabled_items.select(:ai_catalog_item_id))
        end
      end
    end
  end
end
