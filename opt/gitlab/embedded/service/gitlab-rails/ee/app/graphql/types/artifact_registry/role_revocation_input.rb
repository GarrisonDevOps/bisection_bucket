# frozen_string_literal: true

module Types
  module ArtifactRegistry
    class RoleRevocationInput < BaseInputObject
      graphql_name 'ArtifactRegistryRoleRevocationInput'
      description 'Single Artifact Registry role revocation. Names no role: a user holds ' \
        'one role per resource, and revoking removes it.'

      argument :assignee_id, ::Types::GlobalIDType[::User],
        required: true,
        description: 'Global ID of the user to revoke the role from.'

      argument :resource_id, GraphQL::Types::String,
        required: true,
        description: 'UUID of the Artifact Registry resource (repository or namespace) the role is assigned on.'
    end
  end
end
