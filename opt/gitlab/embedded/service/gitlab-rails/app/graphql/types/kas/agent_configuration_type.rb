# frozen_string_literal: true

module Types
  module Kas
    # rubocop: disable Graphql/AuthorizeTypes
    class AgentConfigurationType < BaseObject
      graphql_name 'AgentConfiguration'
      description 'Configuration details for an Agent'

      authorize_granular_token parent_authorizes: :read_cluster_agent

      field :agent_name,
        GraphQL::Types::String,
        null: true,
        description: 'Name of the agent.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
