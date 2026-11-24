# frozen_string_literal: true

module Types
  module Security
    class ProjectTrackedContextInputType < BaseInputObject
      graphql_name 'ProjectTrackedContextInput'
      description 'Input for specifying a project tracked context'

      argument :name, GraphQL::Types::String,
        required: true,
        description: 'Name of the tracked context.'

      argument :type, Types::Security::ProjectTrackedContextTypeEnum,
        required: true,
        description: 'Type of the tracked context.'
    end
  end
end
