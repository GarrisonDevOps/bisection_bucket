# frozen_string_literal: true

module Mutations
  module ArtifactRegistry
    module Role
      class BulkRevoke < BaseMutation
        graphql_name 'ArtifactRegistryRoleBulkRevoke'
        description 'Revokes Artifact Registry roles from users on resources in a single ' \
          'all-or-nothing operation. Users can revoke their own role.'

        argument :revocations, [::Types::ArtifactRegistry::RoleRevocationInput],
          required: true,
          validates: { length: { maximum: ::Types::BaseArgument::MAX_ARRAY_SIZE } },
          description: 'Role revocations to apply. All succeed or none are applied. ' \
            "A maximum of #{::Types::BaseArgument::MAX_ARRAY_SIZE} revocations is allowed per request."

        field :revoked_role_count, GraphQL::Types::Int,
          null: true,
          description: 'Number of role assignments revoked. Present only on success.'

        def resolve(revocations:)
          raise_resource_not_available_error! unless current_user

          result = ::ArtifactRegistry::RevokeRoleAssignmentsService.new(
            current_user: current_user,
            organization: context[:current_organization],
            revocations: resolve_revocations(revocations)
          ).execute

          {
            revoked_role_count: result.payload[:revoked_role_count],
            errors: result.errors
          }
        end

        private

        # Load all assignees in a single query rather than resolving each GID
        # individually, which would be one query per revocation. A missing id
        # maps to a nil assignee, which the service treats as not found. The
        # service's same-organization check is the authorization boundary.
        def resolve_revocations(revocations)
          with_user_ids = revocations.index_with do |revocation|
            revocation[:assignee_id].model_id.to_i
          end
          users_by_id = ::User.id_in(with_user_ids.values).index_by(&:id)

          with_user_ids.map do |revocation, user_id|
            {
              assignee: users_by_id[user_id],
              resource_id: revocation[:resource_id]
            }
          end
        end
      end
    end
  end
end
