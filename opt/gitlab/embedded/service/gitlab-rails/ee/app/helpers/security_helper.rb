# frozen_string_literal: true

module SecurityHelper
  def instance_security_dashboard_data
    {
      no_vulnerabilities_svg_path: image_path('illustrations/empty-state/empty-search-md.svg'),
      empty_state_svg_path: image_path('illustrations/empty-state/empty-radar-md.svg'),
      security_dashboard_empty_svg_path: image_path('illustrations/empty-state/empty-secure-md.svg'),
      project_add_endpoint: security_projects_path,
      project_list_endpoint: security_projects_path,
      instance_dashboard_settings_path: settings_security_dashboard_path,
      vulnerabilities_export_endpoint: expose_path(api_v4_security_vulnerability_exports_path),
      vulnerabilities_pdf_export_endpoint: expose_path(
        api_v4_security_vulnerability_exports_path(params: { export_format: :pdf })
      ),
      can_admin_vulnerability: can_admin_vulnerability?,
      false_positive_doc_url: help_page_path('user/application_security/vulnerabilities/_index.md'),
      can_view_false_positive: can_view_false_positive?,
      has_projects: instance_security_dashboard.has_projects?.to_s,
      dismissal_descriptions: dismissal_descriptions.to_json,
      show_retention_alert: ::Gitlab.com?.to_s, # rubocop:disable Gitlab/AvoidGitlabInstanceChecks -- reason: only needed to show the banner for .com users temporarily
      experiment_features_enabled: instance_experiment_features_enabled?.to_s,
      duo_agent_platform_available: ::Ai::DuoWorkflow.duo_agent_platform_available?(nil).to_s
    }
  end

  def can_view_false_positive?
    ::License.feature_available?(:sast_fp_reduction).to_s
  end

  def instance_experiment_features_enabled?
    ::Gitlab::CurrentSettings.instance_level_ai_beta_features_enabled?
  end

  def instance_security_settings_data
    {
      is_auditor: current_user.auditor?.to_s
    }
  end

  private

  def can_admin_vulnerability?
    (!current_user.auditor? &&
      instance_security_dashboard.has_projects? &&
      instance_security_dashboard.projects.all? do |project|
        Ability.allowed?(current_user, :admin_vulnerability, project)
      end
    ).to_s
  end

  def instance_security_dashboard
    @_instance_security_dashboard ||= InstanceSecurityDashboard.new(current_user)
  end
end
