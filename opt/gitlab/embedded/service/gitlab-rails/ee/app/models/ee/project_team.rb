# frozen_string_literal: true

module EE
  module ProjectTeam
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    def members_with_access_level_or_custom_roles(levels: [], member_role_ids: [])
      return ::User.none unless levels.any? || member_role_ids.any?

      union = ::Gitlab::SQL::Union.new(build_user_id_queries(levels, member_role_ids))
      ::User.where(::User.arel_table[:id].in(Arel.sql("(#{union.to_sql})"))).distinct
    end

    def user_exists_with_access_level_or_custom_roles?(user, levels: [], member_role_ids: [])
      return false unless levels.any? || member_role_ids.any?
      return false unless user

      members_with_access_level_or_custom_roles(levels: levels, member_role_ids: member_role_ids).exists?(id: user.id)
    end

    override :add_members
    def add_members(users, access_level, current_user: nil, expires_at: nil)
      if group_member_lock && !users.all? { |user| bot_type_bypassing_group_member_lock?(user) }
        return false
      end

      super
    end

    override :add_member
    def add_member(
      user, access_level, current_user: nil, expires_at: nil, immediately_sync_authorizations: false,
      skip_authorization: false
    )
      return false if group_member_lock && !bot_type_bypassing_group_member_lock?(user)

      super
    end

    private

    def group_member_lock
      group && group.membership_lock
    end

    def bot_type_bypassing_group_member_lock?(user)
      user.project_bot? ||
        user.security_policy_bot? ||
        user.composite_ai_service_account?
    end

    override :source_members_for_import
    def source_members_for_import(source_project)
      source_project.project_members.where.not(user: source_project.security_policy_bots).to_a
    end

    def build_user_id_queries(levels, member_role_ids)
      queries = []

      if levels.any?
        queries << project.project_authorizations
          .where(access_level: levels)
          .select(Arel.sql('project_authorizations.user_id AS id'))
      end

      return queries unless member_role_ids.any?

      queries << ::Member
        .on_project_and_ancestors(project)
        .where(member_role_id: member_role_ids)
        .select(Arel.sql('members.user_id AS id'))

      if project.group
        queries << ::Authz::UserGroupMemberRole
          .where(group: project.group.traversal_ids, member_role_id: member_role_ids)
          .select(Arel.sql('user_group_member_roles.user_id AS id'))
      end

      queries
    end
  end
end
