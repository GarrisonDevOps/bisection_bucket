# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class ToolCallType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceToolCall'
        description 'AI agent tool usage aggregated for the AI governance dashboard.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :action_type, ::Types::Ai::ToolActionTypeEnum, null: true,
          description: 'Action type of the tool. Null when it is not known.'
        field :count, GraphQL::Types::Int, null: false,
          description: 'Number of tool invocations in the selected timeframe.'
        field :title, GraphQL::Types::String, null: false,
          description: 'Display name of the tool, as shown on the Tool management tab. ' \
            'Same as `toolName` when no rule governs the tool.'
        field :tool_name, GraphQL::Types::String, null: false,
          description: 'Name of the tool rule that governs the tool, ' \
            'or the name recorded in the audit event when no rule governs it.'

        def title
          return object[:tool_name] unless object[:governed]

          ::Ai::ToolRules::ToolPresenter.display_name_for(object[:tool_name])
        end
      end
    end
  end
end
