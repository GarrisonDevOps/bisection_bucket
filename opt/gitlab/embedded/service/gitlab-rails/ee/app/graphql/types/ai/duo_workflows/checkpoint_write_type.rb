# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # rubocop: disable Graphql/AuthorizeTypes -- Parent type (DuoWorkflowEvent) authorization is enough
      class CheckpointWriteType < Types::BaseObject
        graphql_name 'DuoWorkflowCheckpointWrite'
        description 'A pending write associated with a Duo Workflow checkpoint.'

        authorize_granular_token skip_reason: :parent_authorizes

        def self.authorization_scopes
          [:api, :read_api, :ai_features, :ai_workflows]
        end

        field :id, GraphQL::Types::ID,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'ID of the checkpoint write.'

        field :thread_ts, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'LangGraph thread timestamp identifier the write belongs to.'

        field :task, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'LangGraph task identifier the write was made for.'

        field :idx, GraphQL::Types::Int,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Index of the write within the task.'

        field :channel, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'LangGraph channel the write was made to.'

        field :write_type, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'Serialization type of the write data.'

        field :data, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'Write data.'
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
