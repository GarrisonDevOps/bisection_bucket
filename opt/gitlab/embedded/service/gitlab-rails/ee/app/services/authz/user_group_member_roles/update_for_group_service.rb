# frozen_string_literal: true

module Authz
  module UserGroupMemberRoles
    class UpdateForGroupService < BaseService
      include ::Authz::MemberRoleInSharedResource

      attr_reader :user, :group, :member

      def initialize(member)
        @user = member.user
        @group = member.source
        @member = member

        @upserted_for_group_count = 0
        @deleted_for_group_count = 0
        @upserted_for_project_count = 0
        @deleted_for_project_count = 0
      end

      def execute
        # Upserts/deletes one record for the target group and one for each group
        # it was invited to with an assigned member role. Expected volume: at
        # least one to and at most a few hundred records.

        return if member.pending?
        return unless member.active?

        update_user_group_member_roles
        update_user_project_member_roles

        log
      end

      private

      def update_user_group_member_roles
        attrs = [user_group_member_role_in_group] + user_group_member_roles_in_shared_groups
        to_delete_ids, attrs_to_upsert = get_ids_to_delete_and_attrs_to_upsert(attrs)

        unless to_delete_ids.empty?
          @deleted_for_group_count += ::Authz::UserGroupMemberRole.delete_all_with_id(to_delete_ids)
        end

        in_group, in_shared_groups = attrs_to_upsert.partition { |a| a[:shared_with_group_id].nil? }

        unless in_group.empty?
          ::Authz::UserGroupMemberRole
            .upsert_all(in_group, unique_by: %i[user_id group_id])
            .tap { |result| @upserted_for_group_count += result.count }
        end

        ::Authz::UserGroupMemberRole
          .upsert_all(in_shared_groups, unique_by: %i[user_id group_id shared_with_group_id])
          .tap { |result| @upserted_for_group_count += result.count } unless in_shared_groups.empty?
      end

      def update_user_project_member_roles
        return unless ::Feature.enabled?(:cache_user_project_member_roles, member.source.root_ancestor)

        to_delete_ids, attrs_to_upsert = get_ids_to_delete_and_attrs_to_upsert(
          user_project_member_roles_in_shared_projects
        )

        unless to_delete_ids.empty?
          @deleted_for_project_count += ::Authz::UserProjectMemberRole.delete_all_with_id(to_delete_ids)
        end

        ::Authz::UserProjectMemberRole
          .upsert_all(attrs_to_upsert, unique_by: %i[user_id project_id shared_with_group_id])
          .tap { |result| @upserted_for_project_count += result.count } unless attrs_to_upsert.empty?
      end

      def user_group_member_role_in_group
        existing = Authz::UserGroupMemberRole.for_user_in_group(user, group)

        { id: existing&.id, user_id: user.id, group_id: group.id, member_role_id: member.member_role_id,
          shared_with_group_id: nil }
      end

      def user_group_member_roles_in_shared_groups
        # Get all other groups shared to the group where the user is a member.
        # For each, determine which member role (user's member role in the
        # invited group or member role assigned to the invited group) should
        # take effect for the user.
        query = group_group_links
          .join(members).on(user_is_member_of_invited_group(group_group_links[:shared_with_group_id]))
          # Left join with user_group_member_roles to retrieve ids of existing
          # records to delete
          .join(user_group_member_roles, Arel::Nodes::OuterJoin).on(
            user_group_member_roles[:user_id].eq(members[:user_id])
            .and(user_group_member_roles[:group_id].eq(group_group_links[:shared_group_id]))
            .and(user_group_member_roles[:shared_with_group_id].eq(group_group_links[:shared_with_group_id]))
          )
          .project(
            user_group_member_roles[:id],
            members[:user_id],
            group_group_links[:shared_group_id].as('group_id'),
            member_role_id_in_shared_resource(::GroupGroupLink),
            group_group_links[:shared_with_group_id])
          .to_sql

        results = ::Authz::UserGroupMemberRole.connection.select_all query
        results.to_a
      end

      def user_project_member_roles_in_shared_projects
        # For each project shared to the group, determine which member role
        # (user's member role in the invited group or member role assigned to
        # the invited group) should take effect for the user in the project.
        query = project_group_links
          .join(members).on(user_is_member_of_invited_group(project_group_links[:group_id]))
          # Left join with user_project_member_roles to retrieve ids of existing
          # records to delete
          .join(user_project_member_roles, Arel::Nodes::OuterJoin).on(
            user_project_member_roles[:user_id].eq(members[:user_id])
            .and(user_project_member_roles[:project_id].eq(project_group_links[:project_id]))
            .and(user_project_member_roles[:shared_with_group_id].eq(project_group_links[:group_id]))
          )
          .project(
            user_project_member_roles[:id],
            members[:user_id],
            project_group_links[:project_id],
            member_role_id_in_shared_resource(::ProjectGroupLink),
            project_group_links[:group_id].as('shared_with_group_id'))
          .to_sql

        results = ::Authz::UserProjectMemberRole.connection.select_all query
        results.to_a
      end

      def user_is_member_of_invited_group(link_column)
        link_column.eq(group.id)
          .and(members[:user_id].eq(user.id))
          .and(members[:source_id].eq(link_column))
          .and(members[:source_type].eq('Namespace'))
          .and(members[:requested_at].eq(nil))
          .and(members[:state].eq(::Member::STATE_ACTIVE))
      end

      def get_ids_to_delete_and_attrs_to_upsert(attrs)
        attrs = attrs.map { |a| HashWithIndifferentAccess.new(a) }

        to_delete, to_upsert = attrs.partition { |a| a[:member_role_id].nil? }
        to_upsert = to_upsert.map { |a| a.except(:id) }
        to_delete_ids = to_delete.pluck(:id).compact # rubocop:disable Database/AvoidUsingPluckWithoutLimit, CodeReuse/ActiveRecord -- Array#pluck

        [to_delete_ids, to_upsert]
      end

      def user_group_member_roles
        ::Authz::UserGroupMemberRole.arel_table
      end

      def user_project_member_roles
        ::Authz::UserProjectMemberRole.arel_table
      end

      def group_group_links
        ::GroupGroupLink.arel_table
      end

      def project_group_links
        ::ProjectGroupLink.arel_table
      end

      def log
        Gitlab::AppJsonLogger.info(
          user_id: @user.id,
          group_id: @group.id,
          'update_user_group_member_roles.event': 'member created/updated',
          'update_user_group_member_roles.upserted_count': @upserted_for_group_count,
          'update_user_group_member_roles.deleted_count': @deleted_for_group_count,
          'update_user_project_member_roles.upserted_count': @upserted_for_project_count,
          'update_user_project_member_roles.deleted_count': @deleted_for_project_count
        )
      end
    end
  end
end
