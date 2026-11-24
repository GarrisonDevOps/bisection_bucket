# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class SubagentType < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
        graphql_name 'DuoWorkflowSubagent'
        description 'Subagent that a GitLab Duo Agent Platform session can delegate work to, ' \
          'such as a workspace subagent.'

        authorize_granular_token parent_authorizes: :read_duo_workflow

        field :name, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false,
          description: 'Name of the subagent.'

        field :description, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false,
          description: 'Description of the subagent.'

        field :tools, [GraphQL::Types::String],
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false,
          description: 'Names of the tools the subagent declares.'
      end
    end
  end
end
