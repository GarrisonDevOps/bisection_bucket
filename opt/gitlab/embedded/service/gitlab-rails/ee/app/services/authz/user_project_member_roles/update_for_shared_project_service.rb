# frozen_string_literal: true

module Authz
  module UserProjectMemberRoles
    class UpdateForSharedProjectService < BaseService
      include ::Authz::MemberRoleInSharedResource

      attr_reader :shared_project, :shared_with_group

      BATCH_SIZE = 1_000

      def initialize(project_group_link)
        @shared_project = project_group_link.project
        @shared_with_group = project_group_link.group
        @upserted_count = 0
        @deleted_count = 0
      end

      def execute
        # For each member of project_group_link.group:
        # - upsert a record if the member has a member role
        # - delete existing record if the member no longer has a member role

        Member.where( # rubocop:disable CodeReuse/ActiveRecord -- Very specific use-case
          source_id: shared_with_group.id,
          source_type: 'Namespace',
          type: 'GroupMember',
          invite_token: nil
        ).each_batch(of: BATCH_SIZE) do |members_batch|
          attrs = user_project_member_roles_in_shared_projects(members_batch)
          attrs = attrs.map { |a| HashWithIndifferentAccess.new(a) }

          to_delete, to_add = attrs.partition { |a| a[:member_role_id].nil? }
          to_delete = to_delete.filter_map { |a| a[:id] }
          to_add = to_add.map { |a| a.except(:id) }

          @deleted_count += ::Authz::UserProjectMemberRole.delete_all_with_id(to_delete) unless to_delete.empty?

          next if to_add.empty?

          ::Authz::UserProjectMemberRole
            .upsert_all(to_add, unique_by: %i[user_id project_id shared_with_group_id])
            .tap { |result| @upserted_count += result.count }
        end

        log
      end

      private

      def user_project_member_roles_in_shared_projects(members_batch)
        cte = Gitlab::SQL::CTE.new(:members_batch, members_batch.limit(BATCH_SIZE))

        # Get all members of the invited group and for each, determine which
        # member role (user's member role in the invited group or member role
        # assigned to the invited group) should take effect for the user.
        query = cte.apply_to(Member.select(members[:user_id])).arel
          .join(project_group_links).on(members_of_invited_group)
          # Left join with user_project_member_roles to retrieve ids of existing
          # records to delete
          .join(user_project_member_roles, Arel::Nodes::OuterJoin).on(
            user_project_member_roles[:user_id].eq(members[:user_id])
            .and(user_project_member_roles[:project_id].eq(project_group_links[:project_id]))
            .and(user_project_member_roles[:shared_with_group_id].eq(project_group_links[:group_id]))
          )
          .project(
            user_project_member_roles[:id],
            project_group_links[:project_id],
            member_role_id_in_shared_resource(::ProjectGroupLink).as('member_role_id'),
            project_group_links[:group_id].as('shared_with_group_id'))
          # distinct_on and order can be removed when https://gitlab.com/groups/gitlab-org/-/epics/19048 is completed
          .distinct_on(members[:user_id])
          .order(members[:user_id], members[:updated_at].desc) # rubocop:disable CodeReuse/ActiveRecord -- Very specific use-case
          .to_sql

        results = ::Authz::UserProjectMemberRole.connection.select_all query
        results.to_a
      end

      def members_of_invited_group
        project_group_links[:project_id].eq(shared_project.id)
          .and(project_group_links[:group_id].eq(members[:source_id]))
          .and(members[:user_id].not_eq(nil))
          .and(members[:requested_at].eq(nil))
          .and(members[:state].eq(::Member::STATE_ACTIVE))
      end

      def user_project_member_roles
        ::Authz::UserProjectMemberRole.arel_table
      end

      def project_group_links
        ::ProjectGroupLink.arel_table
      end

      def log
        Gitlab::AppJsonLogger.info(
          shared_project_id: @shared_project.id,
          shared_with_group_id: @shared_with_group.id,
          'update_user_project_member_roles.event': 'project_group_link created/updated',
          'update_user_project_member_roles.upserted_count': @upserted_count,
          'update_user_project_member_roles.deleted_count': @deleted_count
        )
      end
    end
  end
end
