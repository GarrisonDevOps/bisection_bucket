# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # rubocop: disable Graphql/AuthorizeTypes -- parent authorization is enough
      class DuoMessageType < Types::BaseObject
        graphql_name 'DuoMessage'
        description 'A message in a Duo Workflow chat log'
        # Only reachable through a checkpoint or a branch, both of which authorize
        # the session first. Without a directive, granular tokens deny every message.
        authorize_granular_token skip_reason: :parent_authorizes

        field :content, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'Content of the message.'

        field :message_type, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: false, description: 'Type of the message.'

        field :message_sub_type, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          experiment: { milestone: '19.0' },
          description: 'Sub-type of the message, used to discriminate among messages of the same type.'

        field :status, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Status of the message.'

        field :tool_info, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Tool information for the message.'

        field :timestamp, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Timestamp of the message.'

        field :correlation_id, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          description:
            'Optional client-supplied identifier echoed back to correlate ' \
            'this message with the request that initiated it.'

        field :message_id, GraphQL::Types::ID, # rubocop:disable GraphQL/ExtractType -- keeping message fields flat for backwards compatibility
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Opaque identifier for the message, assigned by the workflow executor.'

        field :additional_context, [Types::Ai::AdditionalContextType],
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Additional context items attached to the message.'

        field :role, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true, description: 'Role of the message.'

        field :component_name, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          experiment: { milestone: '19.0' },
          description: 'Component name associated with the message.'

        field :subsession_id, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          experiment: { milestone: '19.0' },
          description: 'Subsession ID associated with the message.'

        field :thread_ts, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          experiment: { milestone: '19.3' },
          description: 'Identifier of the checkpoint that introduced the message. ' \
            'Returns `null` if the session does not store incremental checkpoints.'

        field :parent_ts, GraphQL::Types::String,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          experiment: { milestone: '19.3' },
          description: 'Identifier of the checkpoint preceding the one that introduced the message, ' \
            'which is the point a client resumes the session from to regenerate it. ' \
            'Returns `null` if the session does not store incremental checkpoints.'

        field :alternative_count, GraphQL::Types::Int,
          scopes: [:api, :read_api, :ai_features, :ai_workflows],
          null: true,
          experiment: { milestone: '19.3' },
          description: 'The count of alternative branches for a user message -1 (the currently displayed branch). ' \
            'A thread can have multiple branches when a message is retried, ' \
            'and a new branch is created with the same parent_ts as the message being retried. ' \
            'Returns `null` on every message if the session does not store incremental checkpoints.'

        def tool_info
          object.tool_info.to_json
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
