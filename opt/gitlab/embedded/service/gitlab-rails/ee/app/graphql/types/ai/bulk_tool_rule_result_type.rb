# frozen_string_literal: true

module Types
  module Ai
    # rubocop: disable Graphql/AuthorizeTypes -- parent authorization is enough
    class BulkToolRuleResultType < BaseObject
      graphql_name 'BulkToolRuleResult'
      description 'Result for a single tool rule update within a bulk operation.'

      authorize_granular_token skip_reason: :parent_authorizes

      # rubocop: disable GraphQL/ExtractType -- result type intentionally wraps tool_id and tool_rule together
      field :tool_id, GraphQL::Types::String,
        null: false,
        description: 'Tool name that was processed.'

      field :tool_rule, Types::Ai::ToolRuleType,
        null: true,
        description: 'Updated tool rule, if successful.'
      # rubocop: enable GraphQL/ExtractType

      field :errors, [GraphQL::Types::String],
        null: false,
        description: 'Errors for the specific tool rule update.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
