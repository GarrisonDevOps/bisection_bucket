# frozen_string_literal: true

module Types
  module Sbom
    class ComponentVersionType < BaseObject
      graphql_name 'ComponentVersion'
      description 'A software dependency version used by a project'

      authorize :read_component_version

      field :id, ::Types::GlobalIDType[::Sbom::ComponentVersion],
        null: false, description: 'ID of the dependency version.'

      field :version, GraphQL::Types::String,
        null: false, description: 'Version of the dependency.'
    end
  end
end
