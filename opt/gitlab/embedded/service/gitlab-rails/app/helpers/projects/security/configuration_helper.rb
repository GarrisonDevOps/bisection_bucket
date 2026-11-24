# frozen_string_literal: true

module Projects
  module Security
    module ConfigurationHelper
      def vulnerability_training_docs_path
        help_page_path(
          'user/application_security/vulnerabilities/_index.md',
          anchor: 'enable-security-training-for-vulnerabilities'
        )
      end

      # Overridden in EE
      def group_configuration_path; end

      def duo_settings_configuration_path(_can_admin_root_group); end

      def group_owners_path(project)
        root_ancestor = project.root_ancestor

        if can?(current_user, :read_group_member, root_ancestor)
          group_group_members_path(root_ancestor, max_role: "static-#{Gitlab::Access::OWNER}")
        else
          project_project_members_path(project)
        end
      end
    end
  end
end

::Projects::Security::ConfigurationHelper.prepend_mod_with('Projects::Security::ConfigurationHelper')
