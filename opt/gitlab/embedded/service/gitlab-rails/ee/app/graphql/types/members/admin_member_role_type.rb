# frozen_string_literal: true

module Types
  module Members
    class AdminMemberRoleType < BaseObject
      graphql_name 'AdminMemberRole'
      description 'Represents an admin member role'
      include MemberRolesHelper

      implements Types::Members::RoleInterface
      implements Types::Members::CustomRoleInterface

      authorize :read_admin_role
      authorize_granular_token permissions: :read_admin_role, boundary: :instance, boundary_type: :instance,
        assignable_when: [:admin]

      field :enabled_permissions,
        ::Types::Members::CustomizableAdminPermissionType.connection_type,
        null: false,
        experiment: { milestone: '17.7' },
        description: 'Array of all permissions enabled for the custom role.'

      field :ldap_admin_role_links,
        Types::Authz::LdapAdminRoleLinkType.connection_type,
        experiment: { milestone: '18.1' },
        description: 'LDAP admin role sync configurations that will assign the admin member role.'

      field :users_count,
        GraphQL::Types::Int,
        experiment: { milestone: '17.5' },
        description: 'Number of users who have been directly assigned the admin member role.'

      # Authz::AdminRole shares ids with MemberRole, so clients keep getting the
      # MemberRole global ID that the admin role mutations accept.
      def id
        ::Gitlab::GlobalId.build(model_name: 'MemberRole', id: object.id)
      end

      def users_count
        if object.is_a?(::Authz::AdminRole)
          object.user_admin_roles.count
        else
          object.user_member_roles.count
        end
      end

      def details_path
        member_role_details_path(object)
      end

      def enabled_permissions
        if object.is_a?(::Authz::AdminRole)
          object.enabled_permissions.keys
        else
          object.enabled_admin_permissions.keys
        end
      end
    end
  end
end
