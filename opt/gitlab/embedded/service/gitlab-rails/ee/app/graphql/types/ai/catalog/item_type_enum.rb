# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemTypeEnum < BaseEnum
        graphql_name 'AiCatalogItemType'
        description 'Possible item types for AI items.'

        ::Ai::Catalog::Item.item_types.each_key do |item_type|
          value item_type.upcase, description: "#{item_type.humanize}.", value: item_type
        end
      end
    end
  end
end
