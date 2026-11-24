# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemsSortEnum < BaseEnum
        graphql_name 'AiCatalogItemsSort'
        description 'Values for sorting AI Catalog items.'

        value 'CATALOG_PRIORITY', 'By catalog priority order.', value: :catalog_priority
        value 'STAR_COUNT_ASC', 'Star count by ascending order.', value: :star_count_asc
        value 'STAR_COUNT_DESC', 'Star count by descending order.', value: :star_count_desc
        value 'USAGE_COUNT_ASC', 'Last 30-day usage count by ascending order.', value: :usage_count_asc
        value 'USAGE_COUNT_DESC', 'Last 30-day usage count by descending order.', value: :usage_count_desc
      end
    end
  end
end
