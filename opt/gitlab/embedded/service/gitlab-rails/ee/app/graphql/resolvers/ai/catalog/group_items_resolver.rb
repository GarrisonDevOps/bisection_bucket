# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class GroupItemsResolver < BaseResolver
        description 'AI Catalog items that a group can enable.'

        type ::Types::Ai::Catalog::ItemInterface.connection_type, null: false

        argument :item_types, [::Types::Ai::Catalog::ItemTypeEnum],
          required: false,
          description: 'Types of items to retrieve.'

        argument :enabled_by, [::Types::Ai::Catalog::GroupItemEnabledByEnum],
          required: false,
          description: 'Return only items enabled in any of these ways, ' \
            'or not enabled at all when `NONE` is included. ' \
            'Returns all items the group can enable when omitted or empty.'

        argument :search, GraphQL::Types::String,
          required: false,
          description: 'Search items by name and description.'

        argument :sort, ::Types::Ai::Catalog::ItemsSortEnum,
          required: false,
          description: 'Sort order of items.'

        def resolve(**args)
          ::Ai::Catalog::GroupItemsFinder.new(
            current_user,
            object,
            params: args
          ).execute
        end
      end
    end
  end
end
