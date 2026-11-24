# frozen_string_literal: true

module MemberRolesHelper
  include Gitlab::Utils::StrongMemoize
  include ::GitlabSubscriptions::SubscriptionHelper

  def member_roles_data(group = nil)
    {
      new_role_path: new_role_path(group),
      group_full_path: group&.full_path,
      group_id: group&.id,
      current_user_email: current_user.notification_email_or_default,
      ldap_users_path: ldap_admin_role_sync_available? ? admin_users_path(filter: 'ldap_sync') : nil,
      ldap_servers: ldap_servers&.to_json,
      is_saas: gitlab_com_subscription?.to_s,
      sign_in_restrictions_settings_path: (sign_in_restrictions_settings_path unless group)
    }.compact
  end

  def manage_member_roles_path(source)
    ::Members::ManageRolesPath.for(source, current_user)
  end

  def member_role_edit_path(role)
    if use_group_path?(role)
      Gitlab::Routing.url_helpers.edit_group_settings_roles_and_permission_path(role.namespace, role)
    else
      Gitlab::Routing.url_helpers.edit_admin_application_settings_roles_and_permission_path(role)
    end
  end

  def member_role_details_path(role)
    if use_group_path?(role)
      Gitlab::Routing.url_helpers.group_settings_roles_and_permission_path(role.namespace, role)
    else
      Gitlab::Routing.url_helpers.admin_application_settings_roles_and_permission_path(role)
    end
  end

  private

  def use_group_path?(role)
    return false unless gitlab_com_subscription?
    return true if role.is_a?(String)

    !role.admin_related_role?
  end

  def new_role_path(source)
    root_group = source&.root_ancestor
    return unless can?(current_user, :admin_member_role, *[root_group].compact)

    if gitlab_com_subscription?
      # If there's a root group, we're on the group roles and permissions page. Check if the group's plan has custom
      # roles enabled.
      if root_group
        new_group_settings_roles_and_permission_path(root_group) if root_group.custom_roles_enabled?
      else
        new_admin_application_settings_roles_and_permission_path
      end
    # Otherwise, this is self-managed. Check if the license has the custom roles feature.
    elsif License.feature_available?(:custom_roles)
      new_admin_application_settings_roles_and_permission_path
    end
  end

  # LDAP admin role sync is only available if the instance is self-managed, at least one LDAP server is configured,
  # the user can create LDAP admin roles, and the license has custom roles (Ultimate-only feature).
  def ldap_admin_role_sync_available?
    !gitlab_com_subscription? &&
      Gitlab::Auth::Ldap::Config.enabled? &&
      can?(current_user, :create_ldap_admin_role_link) &&
      License.feature_available?(:custom_roles)
  end

  def ldap_servers
    return unless ldap_admin_role_sync_available?

    ::Gitlab::Auth::Ldap::Config.available_servers.map { |server| { text: server.label, value: server.provider_name } }
  end

  # Presence of sign_in_restrictions_settings_path controls whether the security recommendation alert is shown in admin
  # Roles and permissions page.
  def sign_in_restrictions_settings_path
    return unless License.feature_available?(:custom_roles)
    return unless admin_roles_exist?
    return if Gitlab::CurrentSettings.admin_mode && Gitlab::CurrentSettings.require_admin_two_factor_authentication

    general_admin_application_settings_path(anchor: 'js-signin-settings')
  end
  strong_memoize_attr :sign_in_restrictions_settings_path

  def admin_roles_exist?
    if Feature.enabled?(:extract_admin_roles_from_member_roles, :instance)
      Authz::AdminRole.any?
    else
      MemberRole.admin.any?
    end
  end
end
