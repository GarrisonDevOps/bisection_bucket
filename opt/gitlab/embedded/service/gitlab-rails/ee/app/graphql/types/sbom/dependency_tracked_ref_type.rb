# frozen_string_literal: true

module Types
  module Sbom
    class DependencyTrackedRefType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorization checks are implemented on the resolver.
      graphql_name 'DependencyTrackedRef'
      description 'Ref (branch or tag) where a software dependency appears.'
      authorize_granular_token permissions: :read_dependency, boundary: :project, boundary_type: :project

      connection_type_class Types::CountableConnectionType

      field :id, ::Types::GlobalIDType[::Security::ProjectTrackedContext],
        null: false, description: 'Global ID of the tracked ref.'

      field :name, GraphQL::Types::String,
        null: false, description: 'Name of the ref (branch or tag name).',
        method: :context_name

      field :ref_type, ::Types::Security::TrackedRefTypeEnum,
        null: false, description: 'Type of the ref (branch or tag).'

      field :is_default, GraphQL::Types::Boolean,
        null: false, description: 'Indicates whether the ref is the default branch.'

      def ref_type
        object.context_type.to_sym
      end
    end
  end
end
