# frozen_string_literal: true

module Members
  class AllRolesFinder < MemberRoles::RolesFinder
    private

    def member_roles
      # Only return regular custom roles if the user is not allowed to see admin roles.
      can_return_admin_roles? ? MemberRole.all : super
    end
  end
end
