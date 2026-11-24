# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Role
      class Revoke < BaseMutation
        graphql_name 'ArtifactRegistryRoleRevoke'
        description 'Revokes a user\'s Artifact Registry role on a resource. Names no role: ' \
          'a user holds one role per resource, and revoking removes it. ' \
          'Users can revoke their own role.'

        argument :assignee_id, ::Types::GlobalIDType[::User],
          required: true,
          description: 'Global ID of the user to revoke the role from.'

        argument :resource_id, GraphQL::Types::String,
          required: true,
          description: 'UUID of the Artifact Registry resource (repository or namespace) the role is assigned on.'

        def resolve(assignee_id:, resource_id:)
          raise_resource_not_available_error! unless current_user

          assignee = GitlabSchema.object_from_id(assignee_id, expected_type: ::User).sync

          result = ::ArtifactRegistry::RevokeRoleAssignmentsService.new(
            current_user: current_user,
            organization: context[:current_organization],
            revocations: [{ assignee: assignee, resource_id: resource_id }]
          ).execute

          { errors: result.errors }
        end
      end
    end
  end
end
