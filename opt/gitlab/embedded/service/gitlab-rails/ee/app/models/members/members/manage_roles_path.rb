# frozen_string_literal: true

module Members
  # Builds the path for managing member roles (custom roles) for a source's
  # root group, depending on the subscription type and the user's permissions.
  #
  # Shared by `MemberRolesHelper#manage_member_roles_path` and
  # `Projects::ProjectMembers::AppDataSerializer`, so the logic has a single
  # home and the `current_user` dependency is explicit instead of ambient.
  module ManageRolesPath
    module_function

    def for(source, current_user)
      root_group = source&.root_ancestor
      return unless root_group&.custom_roles_enabled?

      # rubocop:disable Gitlab/Authz/PermissionCheck -- Check moved verbatim from
      # MemberRolesHelper; migrating it to a granular permission is out of scope
      # for this refactor.
      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions) &&
          Ability.allowed?(current_user, :admin_group_member, root_group)
        # rubocop:enable Gitlab/Authz/PermissionCheck
        ::Gitlab::Routing.url_helpers.group_settings_roles_and_permissions_path(root_group)
      elsif current_user&.can_admin_all_resources?
        ::Gitlab::Routing.url_helpers.admin_application_settings_roles_and_permissions_path
      end
    end
  end
end
