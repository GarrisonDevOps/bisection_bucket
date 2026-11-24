# frozen_string_literal: true

module Authz
  module MemberRoleInSharedResource
    extend ActiveSupport::Concern

    # Determine effective member role of a user in a shared project or group.
    # Docs: https://docs.gitlab.com/user/custom_roles/#assign-a-custom-role-to-an-invited-group
    #
    # Usage:
    # - ActiveRecord: Member.select(member_role_id_in_shared_resource(::GroupGroupLink))
    # - Arel: Member.arel_table.project(member_role_id_in_shared_resource(::GroupGroupLink))
    #
    # This method assumes the query selects from (project|group)_group_links and
    # members tables joined on (project|group)_group_links.(group_id|shared_with_group_id) = members.source_id
    # like,
    #
    # ...
    # FROM group_group_links ggl
    #   INNER JOIN members m ON
    #     ggl.shared_with_group_id = m.source_id
    #
    # or
    #
    # ...
    # FROM project_group_links pgl
    #   INNER JOIN members m ON
    #     pgl.group_id = m.source_id
    def member_role_id_in_shared_resource(link_model)
      link_table = link_model.arel_table

      group_access_level = link_table[:group_access]
      group_member_role_id = link_table[:member_role_id]

      user_access_level = members[:access_level]
      user_member_role_id = members[:member_role_id]

      Arel::Nodes::Case.new
        .when(user_access_level.gt(group_access_level)).then(group_member_role_id)
        .when(user_access_level.lt(group_access_level)).then(user_member_role_id)
        .when(group_member_role_id.eq(nil)).then(nil)
        .else(user_member_role_id)
    end

    def members
      ::Member.arel_table
    end
  end
end
