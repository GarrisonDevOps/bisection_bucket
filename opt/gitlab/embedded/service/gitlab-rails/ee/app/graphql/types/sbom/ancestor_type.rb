# frozen_string_literal: true

module Types
  module Sbom
    class AncestorType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the parent object.
      graphql_name "AncestorType"

      field :name, GraphQL::Types::String,
        null: true, description: 'Name of the ancestor.'

      field :version, GraphQL::Types::String,
        null: true, description: 'Version of the ancestor.'
    end
  end
end
