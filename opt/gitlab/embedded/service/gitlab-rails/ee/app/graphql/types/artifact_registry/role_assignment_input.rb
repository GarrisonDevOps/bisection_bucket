# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RoleAssignmentInput < BaseInputObject
      graphql_name 'ArtifactRegistryRoleAssignmentInput'
      description 'Single Artifact Registry role assignment.'

      argument :assignee_id, ::Types::GlobalIDType[::User],
        required: true,
        description: 'Global ID of the user to grant the role to.'

      argument :resource_id, GraphQL::Types::String,
        required: true,
        description: 'UUID of the Artifact Registry resource (repository or namespace) the role applies to.'

      argument :role, ::Types::ArtifactRegistry::RoleEnum,
        required: true,
        description: 'Artifact Registry role to grant.'
    end
  end
end
