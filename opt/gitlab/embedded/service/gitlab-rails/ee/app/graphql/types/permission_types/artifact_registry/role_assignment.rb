# frozen_string_literal: true

module Types
  module PermissionTypes
    module ArtifactRegistry
      # `object` is the IAM relationship tuple of the parent ArtifactRegistryRoleAssignment.
      class RoleAssignment < BasePermissionType
        graphql_name 'ArtifactRegistryRoleAssignmentPermissions'
        description 'Actions the current user can take on an Artifact Registry role assignment.'

        authorize_granular_token skip_reason: :parent_authorizes

        permission_field :update_role,
          description: 'Indicates the current user can change the role of the assignment.'

        permission_field :remove_member,
          description: 'Indicates the current user can revoke the assignment from another user.'

        permission_field :leave,
          description: 'Indicates the current user can revoke their own assignment.'

        def update_role
          artifact_registry_role? && unless_last_admin { can_grant_roles? }
        end

        def remove_member
          artifact_registry_role? && unless_last_admin { can_grant_roles? && !own_assignment? }
        end

        def leave
          artifact_registry_role? && unless_last_admin { own_assignment? }
        end

        private

        def unless_last_admin
          return false unless yield
          return true unless namespace_admin_assignment?

          ::Gitlab::Graphql::Lazy.with_value(namespace_admin_ids) do |response|
            next false if response.error?
            next true if response.payload[:many]

            response.payload[:admin_ids] != Set[subject_user_id.to_i]
          end
        end

        # One lookup per request, shared by every row on the page.
        def namespace_admin_ids
          BatchLoader::GraphQL.for(namespace_id).batch(key: [current_user, organization]) do |ids, loader, args|
            user, org = args[:key]
            ids.each do |id|
              loader.call(id, ::ArtifactRegistry::NamespaceAdminIdsService.new(
                current_user: user, organization: org, namespace_id: id
              ).execute)
            end
          end
        end

        def namespace_admin_assignment?
          return false if namespace_id.blank? || admin_role_id.blank?

          object.object&.id == namespace_id && object.role&.id == admin_role_id && subject_user_id.present?
        end

        # Rows such as an owner's organization_admin grant hold no Artifact
        # Registry role, and IAM refuses to change or revoke them.
        def artifact_registry_role?
          ::ArtifactRegistry::Roles.name_for(object.role&.id).present?
        end

        def subject_user_id
          object.subject.identity&.local_id.presence
        end

        def admin_role_id
          ::ArtifactRegistry::Roles.uuid_for(:artifact_admin)
        end

        def namespace_id
          organization&.artifact_registry_namespace_mapping&.ar_namespace_id
        end

        def organization
          context[:current_organization]
        end

        def can_grant_roles?
          ::ArtifactRegistry::AccessManagerCheckService
            .new(current_user: current_user, organization: organization)
            .execute
        end

        def own_assignment?
          return false unless current_user

          subject_user_id == current_user.id.to_s
        end
      end
    end
  end
end
