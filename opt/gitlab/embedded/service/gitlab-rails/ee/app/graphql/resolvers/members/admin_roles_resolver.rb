# frozen_string_literal: true

module Resolvers
  module Members
    class AdminRolesResolver < MemberRoles::RolesResolver
      type Types::Members::AdminMemberRoleType, null: true

      private

      def apply_selected_field_scopes(_member_roles)
        member_roles = super
        member_roles = member_roles.with_ldap_admin_role_links if selects_field?(:ldap_admin_role_links)

        member_roles
      end

      def roles_finder
        ::Members::AdminRolesFinder
      end
    end
  end
end
