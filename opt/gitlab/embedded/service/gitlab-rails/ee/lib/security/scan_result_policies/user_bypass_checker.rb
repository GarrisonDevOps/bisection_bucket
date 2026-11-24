# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class UserBypassChecker
      def initialize(bypass_settings:, project:, current_user:)
        @bypass_settings = bypass_settings
        @project = project
        @current_user = current_user
      end

      def bypass_scope
        return unless current_user

        if users_can_bypass?
          :user
        elsif roles_can_bypass?
          :role
        elsif groups_can_bypass?
          :group
        end
      end

      private

      attr_reader :bypass_settings, :project, :current_user

      def users_can_bypass?
        return false if current_user.project_bot? || current_user.service_account?

        bypass_settings.user_ids.include?(current_user.id)
      end

      def groups_can_bypass?
        group_ids = bypass_settings.group_ids
        return false if group_ids.blank?

        GroupMember.direct_member_of_groups?(group_ids, current_user)
      end

      def roles_can_bypass?
        default_roles = bypass_settings.default_roles
        custom_role_ids = bypass_settings.custom_role_ids

        return false if default_roles.blank? && custom_role_ids.blank?

        levels = default_roles.filter_map { |role| Gitlab::Access.sym_options_with_owner[role.to_sym] }

        project.team.user_exists_with_access_level_or_custom_roles?(
          current_user, levels: levels, member_role_ids: custom_role_ids
        )
      end
    end
  end
end
