# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class ItemConsumerKindEnum < BaseEnum
        graphql_name 'AiCatalogItemConsumerKind'
        description 'The type of configured AI catalog item.'

        ::Ai::Catalog::ItemConsumer.kinds.each_key do |kind|
          value kind.upcase, description: "#{kind.humanize} enablement.", value: kind
        end
      end
    end
  end
end
