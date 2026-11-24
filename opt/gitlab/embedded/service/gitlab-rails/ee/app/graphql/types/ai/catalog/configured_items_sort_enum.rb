# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ConfiguredItemsSortEnum < BaseEnum
        graphql_name 'AiCatalogConfiguredItemsSort'
        description 'Values for sorting configured AI Catalog items.'

        value 'USAGE_COUNT_ASC', 'Last 30-day usage count by ascending order.', value: :usage_count_asc
        value 'USAGE_COUNT_DESC', 'Last 30-day usage count by descending order.', value: :usage_count_desc
      end
    end
  end
end
