# frozen_string_literal: true

module Types
  module Ci
    module Subscriptions
      class ProjectDetailsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- already authorized through parent
        graphql_name 'CiSubscriptionsProjectDetails'

        connection_type_class Types::CountableConnectionType

        field :id, GraphQL::Types::ID,
          null: false,
          description: 'ID of the project.'

        field :name, GraphQL::Types::ID,
          null: false,
          description: 'Full path of the project.'

        field :namespace, ::Types::Ci::Subscriptions::NamespaceDetailsType,
          null: false,
          description: 'Namespace of the project.'

        field :web_url, GraphQL::Types::String,
          null: true,
          description: 'Web URL of the project.'
      end
    end
  end
end
