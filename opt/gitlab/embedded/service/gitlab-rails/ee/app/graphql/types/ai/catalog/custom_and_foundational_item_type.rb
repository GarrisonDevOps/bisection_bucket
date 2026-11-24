# frozen_string_literal: true

module Types
  module Ai
    module Catalog
      class CustomAndFoundationalItemType < BaseUnion
        graphql_name 'AiCatalogCustomAndFoundationalItem'
        description 'An AI catalog item, which is either a custom or foundational item'

        connection_type_class CustomAndFoundationalItemConnectionType

        RESOLVE_TYPES = {
          ::Ai::Catalog::Item::AGENT_TYPE => ::Types::Ai::Catalog::AgentType,
          ::Ai::Catalog::Item::FLOW_TYPE => ::Types::Ai::Catalog::FlowType,
          ::Ai::Catalog::Item::THIRD_PARTY_FLOW_TYPE => ::Types::Ai::Catalog::ThirdPartyFlowType,
          ::Ai::Catalog::Item::FOUNDATIONAL_AGENT_TYPE => ::Types::Ai::FoundationalChatAgentType,
          ::Ai::Catalog::Item::SKILL_TYPE => ::Types::Ai::Catalog::SkillType
        }.freeze

        possible_types ::Types::Ai::Catalog::AgentType,
          ::Types::Ai::Catalog::FlowType,
          ::Types::Ai::Catalog::ThirdPartyFlowType,
          ::Types::Ai::FoundationalChatAgentType,
          ::Types::Ai::Catalog::SkillType

        def self.resolve_type(item, _context)
          RESOLVE_TYPES[item.item_type.to_sym] or raise "Unknown catalog item type: #{item.item_type}" # rubocop:disable Style/AndOr -- Syntax error when || is used
        end
      end
    end
  end
end
