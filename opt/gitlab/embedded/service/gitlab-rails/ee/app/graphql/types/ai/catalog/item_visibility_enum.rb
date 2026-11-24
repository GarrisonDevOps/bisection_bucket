# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemVisibilityEnum < BaseEnum
        graphql_name 'AiCatalogItemVisibility'
        description 'Possible visibility levels for AI catalog items.'

        ::Ai::Catalog::Item.visibilities.each_key do |visibility|
          value visibility.upcase, description: "#{visibility.humanize} visibility.", value: visibility
        end
      end
    end
  end
end
