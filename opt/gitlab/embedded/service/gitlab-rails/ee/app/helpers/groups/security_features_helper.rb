# frozen_string_literal: true

module Groups::SecurityFeaturesHelper
  def group_level_compliance_dashboard_available?(group)
    group.licensed_feature_available?(:group_level_compliance_dashboard) &&
      can?(current_user, :read_compliance_dashboard, group)
  end

  def authorize_compliance_dashboard!
    render_404 unless group_level_compliance_dashboard_available?(group)
  end

  def group_level_credentials_inventory_available?(group)
    can?(current_user, :read_group_credentials_inventory, group)
  end

  def group_level_security_dashboard_data(group)
    {
      projects_endpoint: expose_url(api_v4_groups_projects_path(id: group.id)),
      group_full_path: group.full_path,
      group_security_vulnerabilities_path: group_security_vulnerabilities_path(group),
      no_vulnerabilities_svg_path: image_path('illustrations/empty-state/empty-search-md.svg'),
      empty_state_svg_path: image_path('illustrations/empty-state/empty-dashboard-md.svg'),
      security_dashboard_empty_svg_path: image_path('illustrations/empty-state/empty-secure-md.svg'),
      vulnerabilities_export_endpoint: expose_path(api_v4_security_groups_vulnerability_exports_path(id: group.id)),
      vulnerabilities_pdf_export_endpoint: expose_path(api_v4_security_groups_vulnerability_exports_path(id: group.id,
        params: { export_format: :pdf })),
      can_admin_vulnerability: can?(current_user, :admin_vulnerability, group).to_s,
      can_view_false_positive: group.licensed_feature_available?(:sast_fp_reduction).to_s,
      has_projects: Project.for_group_and_its_subgroups(group).any?.to_s,
      show_retention_alert: ::Gitlab.com?.to_s, # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- We want to display this banner to all GitLab.com users and hide it for self-hosted and dedicated customers.
      dismissal_descriptions: dismissal_descriptions.to_json,
      manage_duo_settings_path: edit_group_path(group, anchor: 'js-gitlab-duo-settings'),
      experiment_features_enabled: (group.namespace_settings&.experiment_features_enabled || false).to_s,
      duo_agent_platform_available: ::Ai::DuoWorkflow.duo_agent_platform_available?(group).to_s
    }
  end

  def group_level_security_inventory_data(group)
    root_group = group.root_ancestor
    can_admin_root_group = can?(current_user, :admin_group, root_group)

    {
      group_full_path: group.full_path,
      group_id: group.id,
      root_group_name: root_group.name,
      can_manage_attributes: can?(current_user, :admin_security_attributes, root_group).to_s,
      can_read_attributes: can?(current_user, :read_security_attribute, group).to_s,
      can_apply_profiles: can?(current_user, :apply_security_scan_profiles, group).to_s,
      can_read_scan_profiles: can?(current_user, :read_security_scan_profiles, root_group).to_s,
      show_new_labels: ::Security::NavIndicator.show_new_labels?(user: current_user, namespace: group).to_s,
      can_admin_root_group: can_admin_root_group.to_s,
      duo_settings_path: (root_group.duo_settings_path if can_admin_root_group),
      group_owners_path: group_group_members_path(root_group, max_role: "static-#{Gitlab::Access::OWNER}"),
      group_manage_attributes_path: group_security_configuration_path(root_group, tab: 'attributes'),
      new_project_path: new_project_path(namespace_id: group.id),
      show_blsa_spotlight: (
        ::Ai::Catalog::FoundationalFlow::BlSecurity::Definition.spotlight_eligible_for?(root_group) &&
        !current_user.dismissed_callout_for_group?(feature_name: :blsa_whats_new_spotlight, group: root_group)
      ).to_s,
      root_group_id: root_group.id
    }
  end

  def group_security_discover_data(group)
    content = 'discover-group-security'

    {
      link: {
        main: new_trial_registration_path(glm_source: 'gitlab.com', glm_content: content),
        secondary: group_billings_path(group.root_ancestor, source: content)
      }
    }
  end
end
