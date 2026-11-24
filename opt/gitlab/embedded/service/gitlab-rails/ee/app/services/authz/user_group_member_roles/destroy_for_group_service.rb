# frozen_string_literal: true

module Authz
  module UserGroupMemberRoles
    class DestroyForGroupService < BaseService
      attr_reader :user, :group

      def initialize(user, group)
        @user = user
        @group = group
        @deleted_for_group_count = 0
        @deleted_for_project_count = 0
      end

      def execute
        destroy_user_group_member_roles
        destroy_user_project_member_roles

        log
      end

      private

      # Deletes one record for the target group and one for each group it was
      # invited to with an assigned member role. Expected volume: less than 100
      # records.
      def destroy_user_group_member_roles
        ids = ::Authz::UserGroupMemberRole.for_user_in_group_and_shared_groups(user, group).ids # rubocop: disable CodeReuse/ActiveRecord -- Very specific use case.

        return if ids.empty?

        @deleted_for_group_count = ::Authz::UserGroupMemberRole.delete_all_with_id(ids)
      end

      # Deletes one record for each project the group was invited to with an
      # assigned member role. Expected volume: less than 100 records.
      def destroy_user_project_member_roles
        return if ::Feature.disabled?(:cache_user_project_member_roles, group.root_ancestor)

        ids = ::Authz::UserProjectMemberRole.for_user_shared_with_group(user, group).ids # rubocop: disable CodeReuse/ActiveRecord -- Very specific use case.

        return if ids.empty?

        @deleted_for_project_count = ::Authz::UserProjectMemberRole.delete_all_with_id(ids)
      end

      def log
        Gitlab::AppJsonLogger.info(
          user_id: @user.id,
          group_id: @group.id,
          'update_user_group_member_roles.event': 'member deleted',
          'update_user_group_member_roles.upserted_count': 0,
          'update_user_group_member_roles.deleted_count': @deleted_for_group_count,
          'update_user_project_member_roles.deleted_count': @deleted_for_project_count
        )
      end
    end
  end
end
