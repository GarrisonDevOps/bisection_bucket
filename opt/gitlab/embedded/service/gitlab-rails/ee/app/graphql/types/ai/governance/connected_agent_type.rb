# frozen_string_literal: true

module Types
  module Ai
    module Governance
      # Reachable only through fields that already authorize against the
      # group or project, so no object-level authorization is needed here.
      class ConnectedAgentType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent field authorizes
        graphql_name 'AiGovernanceConnectedAgent'
        description 'Registered external agents of one type, with their session activity.'

        authorize_granular_token skip_reason: :parent_authorizes

        field :active_count, GraphQL::Types::Int, null: false,
          description: 'Registered machines whose identity has not been revoked.'
        field :agent_type, GraphQL::Types::String, null: false,
          description: 'External agent type, for example `claude-code`.'
        field :identity_count, GraphQL::Types::Int, null: false,
          description: 'Registered machines of the agent type, revoked ones included.'
        field :last_session_at, Types::TimeType, null: true,
          description: 'When a machine of the agent type last opened a session, across all time.'
        field :revoked_count, GraphQL::Types::Int, null: false,
          description: 'Registered machines whose identity was revoked.'
        field :session_count, GraphQL::Types::Int, null: false,
          description: 'Sessions opened by these machines in the selected timeframe.'
        field :user_count, GraphQL::Types::Int, null: false,
          description: 'Distinct users with a registered machine of the agent type.'
      end
    end
  end
end
