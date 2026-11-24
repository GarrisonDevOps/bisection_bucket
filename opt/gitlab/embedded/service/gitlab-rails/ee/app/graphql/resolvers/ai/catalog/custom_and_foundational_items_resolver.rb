# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class CustomAndFoundationalItemsResolver < BaseResolver
        include LooksAhead

        description 'AI Catalog items, including custom and foundational items.'

        type ::Types::Ai::Catalog::CustomAndFoundationalItemType.connection_type, null: false

        argument :item_types, [::Types::Ai::Catalog::ItemTypeEnum],
          required: false,
          description: 'Types of items to retrieve.'

        argument :search, GraphQL::Types::String,
          required: false,
          description: 'Search items by name and description.'

        argument :sort, ::Types::Ai::Catalog::ItemsSortEnum,
          required: false,
          default_value: :catalog_priority,
          description: 'Sort order of items.'

        def resolve_with_lookahead(**args)
          items = ::Ai::Catalog::ItemsFinder.new(
            current_user,
            params: finder_params(args)
          ).execute

          apply_lookahead(items)
        end

        def finder_params(params)
          params[:organization] = current_organization
          params[:include_foundational_items] = true
          params
        end
      end
    end
  end
end
