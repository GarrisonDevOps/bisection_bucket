# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class ProjectItemsResolver < BaseResolver
        description 'AI Catalog items for a project.'

        type ::Types::Ai::Catalog::ItemInterface.connection_type, null: false

        argument :item_types, [::Types::Ai::Catalog::ItemTypeEnum],
          required: false,
          description: 'Types of items to retrieve.'

        argument :enabled,
          GraphQL::Types::Boolean,
          required: false,
          description: 'Include only items that are enabled or disabled in the project.'

        argument :all_available,
          GraphQL::Types::Boolean,
          required: false,
          description: 'Include public items from the AI Catalog.'

        argument :search, GraphQL::Types::String,
          required: false,
          description: 'Search items by name and description.'

        argument :sort, ::Types::Ai::Catalog::ItemsSortEnum,
          required: false,
          description: 'Sort order of items.'

        def resolve(**args)
          ::Ai::Catalog::ProjectItemsFinder.new(
            current_user,
            object,
            params: args
          ).execute
        end
      end
    end
  end
end
