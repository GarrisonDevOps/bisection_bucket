# frozen_string_literal: true

module Types
  module Sbom
    class DependencyPathPartialType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the parent object.
      graphql_name 'DependencyPathPartial'
      description 'Ancestor path partial of a given dependency.'

      field :name, GraphQL::Types::String,
        null: false, description: 'Name of the dependency.'

      field :version, GraphQL::Types::String,
        null: false, description: 'Version of the dependency.'
    end
  end
end
