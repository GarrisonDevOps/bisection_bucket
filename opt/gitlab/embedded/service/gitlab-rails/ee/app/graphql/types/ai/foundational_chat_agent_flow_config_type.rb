# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- Always public
    class FoundationalChatAgentFlowConfigType < ::Types::BaseObject
      graphql_name 'AiFoundationalChatAgentFlowConfig'
      description 'Flow versioning parameters for a foundational chat agent.'
      authorize_granular_token parent_authorizes: :read_ai_catalog_item

      # rubocop:disable GraphQL/ExtractType -- mirrors the StartWorkflowRequest payload sent to DWS
      field :flow_config_id, GraphQL::Types::String, null: true,
        description: 'Flow config ID sent to the Duo Workflow Service.'
      field :flow_config_schema_version, GraphQL::Types::String, null: true,
        description: 'Flow config schema version sent to the Duo Workflow Service.'
      field :flow_version, GraphQL::Types::String, null: true,
        description: 'Flow version sent to the Duo Workflow Service.'
      # rubocop:enable GraphQL/ExtractType
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
