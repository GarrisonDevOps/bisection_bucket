# frozen_string_literal: true

module Types
  module ComplianceManagement
    class ProjectInputType < BaseInputObject
      graphql_name 'ComplianceFrameworkProjectInput'

      argument :add_projects,
        [GraphQL::Types::Int],
        required: true,
        description: 'IDs of the projects to add to the compliance framework.'

      argument :remove_projects,
        [GraphQL::Types::Int],
        required: true,
        description: 'IDs of the projects to remove from the compliance framework.'
    end
  end
end
