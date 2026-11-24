# frozen_string_literal: true

module EE
  module Projects
    module ProjectMembers
      module AppDataSerializer
        extend ::Gitlab::Utils::Override
        include ::GitlabSubscriptions::MemberManagement::PromotionManagementUtils

        override :app_data
        def app_data(
          invited:, links:, access_requests:, pending_members_count:
        )
          super.merge(
            manage_member_roles_path: ::Members::ManageRolesPath.for(project, current_user),
            can_approve_access_requests: can_approve_access_requests,
            namespace_user_limit: ::Namespaces::FreeUserCap.dashboard_limit,
            promotion_request: { enabled: member_promotion_management_enabled?, total_items: pending_members_count }
          )
        end

        private

        def can_approve_access_requests
          return true if project.personal?

          !::Namespaces::FreeUserCap::Enforcement.new(project.root_ancestor).reached_limit?
        end

        override :available_roles
        def available_roles
          custom_roles = ::MemberRoles::RolesFinder.new(current_user, parent: project).execute
          custom_role_options = custom_roles.map do |member_role|
            { title: member_role.name, value: "custom-#{member_role.id}" }
          end

          super + custom_role_options
        end
      end
    end
  end
end
