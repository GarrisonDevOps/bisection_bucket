# frozen_string_literal: true

module EE
  module Authz
    module HasRoles
      def custom_role_abilities_too_high?(current_user:, target_member_role_id:)
        return false if current_user.can_admin_all_resources?
        return false unless target_member_role_id

        current_user_access_level = max_member_access_for_user(current_user)

        return false if ::Gitlab::Access::OWNER == current_user_access_level

        current_user_member_role = ::Member.highest_role(current_user, self)&.member_role
        target_member_role = MemberRole.find_by_id(target_member_role_id)

        current_user_role_abilities = member_role_abilities(current_user_member_role) +
          custom_abilities_included_with_base_access_level(current_user_access_level)

        target_member_role_abilities = member_role_abilities(target_member_role)

        (target_member_role_abilities - current_user_role_abilities).present?
      end

      private

      def custom_abilities_included_with_base_access_level(access_level)
        abilities = []
        customizable_permissions = MemberRole.all_customizable_permissions
        enabled_for_key = :"enabled_for_#{self.class.name.demodulize.downcase}_access_levels"

        customizable_permissions.each do |name, definition|
          next unless definition.fetch(enabled_for_key, []).include?(access_level)

          abilities << name
        end

        abilities
      end

      def member_role_abilities(member_role)
        return [] unless member_role

        member_role.enabled_permissions.keys
      end
    end
  end
end
