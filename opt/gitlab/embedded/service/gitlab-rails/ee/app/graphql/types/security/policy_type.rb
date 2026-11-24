# frozen_string_literal: true

module Types
  module Security
    class PolicyType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization handled by parent type
      graphql_name 'SecurityPolicy'
      description 'Represents a security policy'

      field :id, GraphQL::Types::ID,
        null: false,
        description: 'ID of the security policy.'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Name of the security policy.'
    end
  end
end
