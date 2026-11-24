# frozen_string_literal: true

module Types
  module Clusters
    module Agents
      module Authorizations
        class UserAccessType < BaseObject # rubocop:disable Graphql/AuthorizeTypes
          graphql_name 'ClusterAgentAuthorizationUserAccess'

          authorize_granular_token parent_authorizes: :read_cluster_agent

          field :agent, Types::Clusters::AgentType,
            description: 'Authorized cluster agent.',
            null: true

          field :config, GraphQL::Types::JSON, # rubocop:disable Graphql/JSONType
            description: 'Configuration for the authorized project.',
            null: true
        end
      end
    end
  end
end
