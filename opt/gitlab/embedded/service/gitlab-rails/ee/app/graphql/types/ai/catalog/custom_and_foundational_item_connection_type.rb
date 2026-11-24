# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class CustomAndFoundationalItemConnectionType < GraphQL::Types::Relay::BaseConnection # rubocop: disable Graphql/AuthorizeTypes -- authorized in resolver
        graphql_name 'AiCatalogCustomAndFoundationalItemConnectionType'

        def nodes
          results = super

          results.map do |result|
            if result.item_type.to_sym == ::Ai::Catalog::Item::FOUNDATIONAL_AGENT_TYPE
              ::Ai::FoundationalChatAgent.find_by(reference: result.reference) # rubocop:disable CodeReuse/ActiveRecord -- Not ActiveRecord
            else
              result
            end
          end
        end
      end
    end
  end
end
