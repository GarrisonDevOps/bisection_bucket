# frozen_string_literal: true

module EE::Groups::GroupMembersHelper
  extend ::Gitlab::Utils::Override

  override :group_members_list_data
  def group_members_list_data(group, _members, _pagination = {})
    super.merge!({
      disable_two_factor_path: group_two_factor_auth_path(group),
      ldap_override_path: override_group_group_member_path(group, ':id')
    })
  end

  # rubocop:disable Metrics/ParameterLists -- all arguments needed
  override :group_members_app_data
  def group_members_app_data(
    group,
    members:,
    invited:,
    access_requests:,
    banned:,
    include_relations:,
    pending_members_count:,
    placeholder_users:,
    params: {}
  )
    super.merge!({
      can_export_members: can?(current_user, :export_group_memberships, group),
      export_csv_path: export_csv_group_group_members_path(group),
      can_filter_by_enterprise: group.domain_verification_available? && can?(current_user, :admin_group_member, group),
      banned: group_members_list_data(group, banned),
      manage_member_roles_path: manage_member_roles_path(group),
      promotion_request: { enabled: member_promotion_management_enabled?, total_items: pending_members_count },
      can_approve_access_requests: !::Namespaces::FreeUserCap::Enforcement.new(group.root_ancestor).reached_limit?,
      namespace_user_limit: ::Namespaces::FreeUserCap.dashboard_limit,
      restrict_reassignment_to_enterprise: group.any_enterprise_users?,
      allow_non_enterprise_placeholder_reassignment: group.allow_non_enterprise_placeholder_reassignment?
    })
  end
  # rubocop:enable Metrics/ParameterLists

  def group_member_header_subtext(group)
    unless current_user && can?(current_user, :invite_group_members, group)
      if Gitlab::Saas.feature_available?(:group_disable_invite_members)
        return cannot_invite_member_subtext(group.name, "group owner")
      end

      return cannot_invite_member_subtext(group.name, "instance administrator")

    end

    if ::Namespaces::FreeUserCap::Enforcement.new(group.root_ancestor).enforce_cap? &&
        can?(current_user, :admin_group_member, group.root_ancestor)
      super + member_header_manage_namespace_members_text(group.root_ancestor)
    else
      super
    end
  end

  override :available_group_roles
  def available_group_roles(group)
    custom_roles = ::MemberRoles::RolesFinder.new(current_user, parent: group).execute
    custom_role_options = custom_roles.map do |member_role|
      { title: member_role.name, value: "custom-#{member_role.id}" }
    end

    super + custom_role_options
  end

  def qualified_for_user_confirmation_bypass(group)
    group.domain_verification_available?
  end

  override :allow_group_owner_enterprise_bypass?
  def allow_group_owner_enterprise_bypass?(group)
    strong_memoize_with(:allow_group_owner_enterprise_bypass, group) do
      next false unless qualified_for_user_confirmation_bypass(group) && group&.namespace_settings

      group.namespace_settings.allow_enterprise_bypass_placeholder_confirmation
    end
  end

  private

  def cannot_invite_member_subtext(group_name, actor)
    safe_format(
      _("You cannot invite a new member to %{strong_start}%{group_name}%{strong_end}. " \
        "User invitations are disabled by the %{actor}."),
      tag_pair(tag.strong, :strong_start, :strong_end), group_name: group_name, actor: actor)
  end
end
