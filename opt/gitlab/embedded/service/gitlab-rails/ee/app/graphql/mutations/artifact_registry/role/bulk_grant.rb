# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Role
      class BulkGrant < BaseMutation
        graphql_name 'ArtifactRegistryRoleBulkGrant'
        description 'Grants Artifact Registry roles to users on resources in a single ' \
          'all-or-nothing operation. Replaces any role a user already holds on that resource.'

        argument :assignments, [::Types::ArtifactRegistry::RoleAssignmentInput],
          required: true,
          validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: 'Role assignments to grant. All succeed or none are written. ' \
            "A maximum of #{::Types::BaseArgument::MAX_ARRAY_SIZE} assignments is allowed per request."

        field :granted_role_count, GraphQL::Types::Int,
          null: true,
          description: 'Number of role assignments granted. Present only on success.'

        def resolve(assignments:)
          raise_resource_not_available_error! unless current_user

          result = ::ArtifactRegistry::GrantRoleAssignmentsService.new(
            current_user: current_user,
            organization: context[:current_organization],
            assignments: resolve_assignments(assignments)
          ).execute

          {
            granted_role_count: result.payload[:granted_role_count],
            errors: result.errors
          }
        end

        private

        # Load all assignees in a single query rather than resolving each GID
        # individually, which would be one query per assignment. A missing id
        # maps to a nil assignee, which the service treats as not found. The
        # service's same-organization check is the authorization boundary.
        def resolve_assignments(assignments)
          with_user_ids = assignments.index_with do |assignment|
            assignment[:assignee_id].model_id.to_i
          end
          users_by_id = ::User.id_in(with_user_ids.values).index_by(&:id)

          with_user_ids.map do |assignment, user_id|
            {
              assignee: users_by_id[user_id],
              resource_id: assignment[:resource_id],
              role: assignment[:role]
            }
          end
        end
      end
    end
  end
end
