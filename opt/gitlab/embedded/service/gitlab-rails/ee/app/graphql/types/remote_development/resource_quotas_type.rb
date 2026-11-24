# frozen_string_literal: true

# rubocop: disable Graphql/AuthorizeTypes -- because ResourceQuotas is, and should only be, accessible via WorkspacesAgentConfigType
module Types
  module RemoteDevelopment
    class ResourceQuotasType < ::Types::BaseObject
      graphql_name 'ResourceQuotas'
      description 'Resource quotas of a workspace.'

      field :cpu, GraphQL::Types::String,
        null: false, description: 'Number of cpu cores.'
      field :memory, GraphQL::Types::String,
        null: false, description: 'Bytes of memory.'
    end
  end
end
# rubocop: enable Graphql/AuthorizeTypes
