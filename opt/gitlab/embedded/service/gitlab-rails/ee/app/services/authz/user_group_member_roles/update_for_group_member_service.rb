# frozen_string_literal: true

module Authz
  module UserGroupMemberRoles
    class UpdateForGroupMemberService < BaseService
      include ::Gitlab::Utils::StrongMemoize

      attr_reader :member, :old_values_map

      def initialize(member, old_values_map: nil)
        @member = member
        @old_values_map = old_values_map
      end

      def execute
        return unless member.source.is_a?(::Group)
        return unless with_possible_changes_after_update? || with_possible_changes_after_create?

        member.run_after_commit_or_now do
          UpdateForGroupWorker.perform_async(id)
        end
      end

      private

      def with_possible_changes_after_create?
        member.member_role || group_has_member_role_in_another_group? || group_has_member_role_in_project?
      end

      def with_possible_changes_after_update?
        return false unless old_values_map

        member_role_changed = member.member_role_id != old_values_map[:member_role_id]
        access_level_changed = member.access_level != old_values_map[:access_level]

        return true if member_role_changed

        access_level_changed && (group_has_member_role_in_another_group? || group_has_member_role_in_project?)
      end

      def group_has_member_role_in_another_group?
        ::GroupGroupLink.for_shared_with_groups(member.source_id).with_custom_role.exists?
      end
      strong_memoize_attr :group_has_member_role_in_another_group?

      def group_has_member_role_in_project?
        return false if ::Feature.disabled?(:cache_user_project_member_roles, member.source.root_ancestor)

        ::ProjectGroupLink.in_group(member.source_id).with_custom_role.exists?
      end
      strong_memoize_attr :group_has_member_role_in_project?
    end
  end
end
