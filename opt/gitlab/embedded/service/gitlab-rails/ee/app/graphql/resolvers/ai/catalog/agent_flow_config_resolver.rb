# frozen_string_literal: true

module Resolvers
  module Ai
    module Catalog
      class AgentFlowConfigResolver < BaseResolver
        type ::GraphQL::Types::String, null: true

        argument :agent_version_id, ::Types::GlobalIDType[::Ai::Catalog::ItemVersion],
          required: true,
          description: 'Global ID of the agent version to use.'

        argument :flow_config_type, Types::Ai::Catalog::FlowConfigTypeEnum,
          required: true,
          description: 'Type of flow configuration to generate.'

        def resolve(flow_config_type:, agent_version_id:)
          agent_version = GitlabSchema.object_from_id(agent_version_id).sync

          return unless agent_version && Ability.allowed?(current_user, :read_ai_catalog_item, agent_version)

          result = ::Ai::Catalog::Agents::BuildFlowConfigService.new(
            project: agent_version.item.project,
            current_user: current_user,
            params: {
              agent_version: agent_version,
              flow_config_type: flow_config_type
            }
          ).execute

          result.payload[:flow_config]
        end
      end
    end
  end
end
