# frozen_string_literal: true

module Types
  module Sbom
    class DependencyPathType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the parent object.
      graphql_name 'DependencyPath'
      description 'Ancestor path of a given dependency.'

      field :path, [DependencyPathPartialType],
        null: false, description: 'Name of the dependency.'

      field :is_cyclic, GraphQL::Types::Boolean,
        null: false, description: 'Indicates if the path is cyclic.'

      def path
        object[:path].map do |occurrence|
          { name: occurrence.component_name, version: occurrence.version }
        end
      end
    end
  end
end
