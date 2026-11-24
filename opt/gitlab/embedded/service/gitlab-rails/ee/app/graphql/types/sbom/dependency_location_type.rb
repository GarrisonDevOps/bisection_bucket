# frozen_string_literal: true

module Types
  module Sbom
    class DependencyLocationType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the resolver.
      graphql_name 'DependencyLocation'
      description 'Location of a software dependency within a project.'
      authorize_granular_token permissions: :read_dependency, boundary: :project, boundary_type: :project

      field :occurrence_id, ::Types::GlobalIDType[::Sbom::Occurrence],
        null: false, description: 'Global ID of the SBOM occurrence.',
        method: :to_global_id

      field :location, Types::Sbom::LocationType,
        null: true, description: 'Information about where the dependency is located.'

      field :has_dependency_paths, GraphQL::Types::Boolean,
        null: false, description: 'Indicates whether the dependency has any dependency paths.',
        method: :has_dependency_paths?

      field :project, Types::ProjectType,
        null: true, description: 'Project containing the dependency.'
    end
  end
end
