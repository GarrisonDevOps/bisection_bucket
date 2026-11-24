# frozen_string_literal: true

module GroupLinksHelper
  def group_link_role_selector_data(group, current_user)
    data = { standard_roles: group.access_level_roles }

    if group.custom_roles_enabled?
      data[:custom_roles] = MemberRoles::RolesFinder.new(current_user, { parent: group })
        .execute.map { |role| { member_role_id: role.id, name: role.name, base_access_level: role.base_access_level } }
    end

    data
  end

  def group_link_role_name(group_link)
    if group_link.member_role_id.present? && group_link.group.custom_roles_enabled?
      group_link.member_role.name
    else
      group_link.human_access
    end
  end
end
