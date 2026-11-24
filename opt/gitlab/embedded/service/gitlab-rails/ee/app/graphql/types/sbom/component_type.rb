# frozen_string_literal: true

module Types
  module Sbom
    class ComponentType < BaseObject
      graphql_name 'Component'
      description 'A software dependency used by a project'

      authorize :read_component

      field :id, ::Types::GlobalIDType[::Sbom::Component],
        null: false, description: 'ID of the dependency.'

      field :name, GraphQL::Types::String,
        null: false, description: 'Name of the dependency.'
    end
  end
end
