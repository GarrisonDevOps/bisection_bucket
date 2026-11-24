# frozen_string_literal: true

module Types
  module Sbom
    class DependencyType < BaseObject
      graphql_name 'Dependency'
      description 'A software dependency used by a project'

      implements Types::Sbom::DependencyInterface

      authorize :read_dependency

      field :has_dependency_paths, GraphQL::Types::Boolean,
        null: false, description: 'Indicates whether the dependency has any dependency paths.',
        method: :has_dependency_paths?, experiment: { milestone: '18.4' }

      field :tracked_refs_count, GraphQL::Types::Int,
        null: false, description: 'Number of tracked refs (branches or tags) associated with the dependency.',
        experiment: { milestone: '19.2' }

      def tracked_refs_count
        object.occurrence_refs.size
      end

      def vulnerability_count
        object.vulnerabilities&.size || 0
      end
    end
  end
end
