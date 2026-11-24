# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class FlowConfigTypeEnum < BaseEnum
        graphql_name 'AiCatalogFlowConfigType'
        description 'Possible flow configuration types for AI Catalog agents.'

        value 'CHAT', description: 'Chat flow configuration.', value: 'chat'
      end
    end
  end
end
