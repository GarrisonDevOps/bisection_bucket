# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # rubocop: disable Graphql/AuthorizeTypes -- the resolver authorizes the session first
      class BranchType < Types::BaseObject
        graphql_name 'DuoWorkflowBranch'
        description 'Alternative branch of a Duo Agent Platform session, created by retrying a message'
        authorize_granular_token skip_reason: :parent_authorizes

        field :fork_thread_ts, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          description: 'Identifier of the checkpoint to resume the session from to switch to the branch.'

        field :messages, [Types::Ai::DuoWorkflows::DuoMessageType],
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false,
          description: 'Messages the branch added after the point it diverged, oldest first.'

        def messages
          # Skip anything that is not a message, as the checkpoint read does: a fold
          # over blob data carries whatever the gateway wrote.
          object.messages.filter_map do |message|
            ::Ai::DuoWorkflows::WorkflowCheckpointEventPresenter.build_duo_message(message) if message.is_a?(Hash)
          end
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
