# frozen_string_literal: true

module Types
  module Ci
    module Subscriptions
      class NamespaceDetailsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- already authorized through parent
        graphql_name 'CiSubscriptionsProjectNamespaceDetails'

        connection_type_class Types::CountableConnectionType

        field :id, GraphQL::Types::ID,
          null: false,
          description: 'ID of the project.'

        field :name, GraphQL::Types::ID,
          null: false,
          description: 'Full path of the project.'
      end
    end
  end
end
