# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- Always public
    class FoundationalChatAgentType < ::Types::BaseObject
      graphql_name 'AiFoundationalChatAgent'
      description 'Core Agent available for GitLab features.'

      authorize_granular_token permissions: :read_ai_catalog_item, boundary: :user, boundary_type: :user

      field :avatar_url, GraphQL::Types::String, null: true,
        description: 'Avatar URL of the foundational chat agent.'
      field :description, GraphQL::Types::String, null: false,
        description: 'Description of the agent.'
      field :flow_config, ::Types::Ai::FoundationalChatAgentFlowConfigType, null: true,
        description: 'Flow versioning parameters used when starting a workflow for this agent. ' \
          'Null for agents that resolve versioning elsewhere (e.g. AI Catalog-backed agents).'
      field :id, ::Types::GlobalIDType[::Ai::FoundationalChatAgent], null: false,
        description: 'Global ID of the foundational chat agent.'
      field :item_type, ::Types::Ai::Catalog::ItemTypeEnum, null: false,
        description: 'Type of the agent.'
      field :name, GraphQL::Types::String, null: false, description: 'Name of the agent.'
      field :reference, GraphQL::Types::String, null: false,
        description: 'Reference ID of the agent.'
      field :reference_with_version, GraphQL::Types::String,
        null: true, description: 'Versioned reference of the agent.'
      field :selectable_in_chat, GraphQL::Types::Boolean, null: false,
        description: 'Whether the agent is selectable in the chat agent selection UI.'
      field :system_prompt, GraphQL::Types::String, null: true,
        description: 'System prompt for the agent.'
      field :tools, [::Types::Ai::Catalog::BuiltInToolType], null: false,
        description: 'List of built-in tools enabled for the agent.', method: :built_in_tools
      field :version, GraphQL::Types::String, null: true, description: 'Version of the agent.'
      field :visibility, ::Types::Ai::Catalog::ItemVisibilityEnum, null: false,
        description: 'Visibility of the agent in the catalog.'

      FlowConfigData = Data.define(:flow_config_id, :flow_config_schema_version, :flow_version)

      def avatar_url
        return unless object.avatar

        ActionController::Base.helpers.image_path("bot_avatars/#{object.avatar}")
      end

      def flow_config
        params = ::Ai::DuoWorkflows::FoundationalFlowStartParamsResolver
          .resolve_for_foundational_chat_agent(object.workflow_definition)
        return if params.blank?

        FlowConfigData.new(**params)
      end
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
