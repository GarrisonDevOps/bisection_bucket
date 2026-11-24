# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- because NetworkPolicyEgress is, and should only be, accessible via WorkspacesAgentConfigType
module Types
  module RemoteDevelopment
    class NetworkPolicyEgressType < ::Types::BaseObject
      graphql_name 'NetworkPolicyEgress'

      field :allow, GraphQL::Types::String,
        null: false, description: 'IP range to allow traffic from.'
      field :except, [GraphQL::Types::String],
        null: true, description: 'List of IP ranges to exclude from the `allow` range.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
