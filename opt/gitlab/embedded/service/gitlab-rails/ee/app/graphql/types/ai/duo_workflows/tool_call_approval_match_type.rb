# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class ToolCallApprovalMatchType < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
        graphql_name 'DuoWorkflowToolCallApprovalMatch'
        description 'Approval match details for a Duo Workflow tool call.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :matched, GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates the tool call matches a stored approval.'

        field :match_type, Types::Ai::DuoWorkflows::ToolCallApprovalMatchMechanismEnum,
          null: true,
          description: 'Mechanism that produced the match, null when unmatched.'

        field :matched_pattern, GraphQL::Types::String,
          null: true,
          description: 'Glob pattern that produced the match, present only for pattern matches.'
      end
    end
  end
end
