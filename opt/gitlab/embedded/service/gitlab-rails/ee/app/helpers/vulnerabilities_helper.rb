# frozen_string_literal: true

module VulnerabilitiesHelper
  include ::API::Helpers::RelatedResourcesHelpers

  FINDING_FIELDS = %i[metadata identifiers name issue_feedback merge_request_feedback project scanner uuid details dismissal_feedback false_positive state_transitions issue_links merge_request_links].freeze

  def vulnerability_details_app_data(vulnerability, pipeline, project, policy_dismissals)
    {
      vulnerability: vulnerability_details_json(vulnerability, pipeline, policy_dismissals),
      can_view_false_positive: project.licensed_feature_available?(:sast_fp_reduction).to_s,
      commit_path_template: commit_path_template(project),
      project_full_path: project.full_path,
      default_branch: project.default_branch,
      customize_jira_issue_enabled: project.jira_integration&.customize_jira_issue_enabled.to_s,
      experiment_features_enabled: (!!project.root_ancestor&.experiment_features_enabled).to_s,
      duo_agent_platform_available: ::Ai::DuoWorkflow.duo_agent_platform_available?(project).to_s,
      can_create_secret_from_leaked_token: can_create_secret_from_leaked_token?(project, vulnerability.report_type).to_s,
      duo_secret_detection_fp_enabled: project.duo_secret_detection_fp_enabled.to_s,
      duo_sast_false_positive_detection_enabled: project.duo_sast_fp_detection_enabled.to_s,
      duo_vulnerability_context_analysis_enabled: project.project_setting.duo_vulnerability_context_analysis_enabled.to_s,
      secrets_manager_cta: secrets_manager_vulnerability_cta_data(project, vulnerability.report_type).to_json
    }
  end

  # Only secret detection pages can offer the rotation, so other report types skip the entitlement lookup.
  def can_create_secret_from_leaked_token?(project, report_type)
    return false unless report_type == 'secret_detection'

    can?(current_user, :create_project_secrets, project)
  end

  def vulnerability_details_json(vulnerability, pipeline, policy_dismissals)
    vulnerability_details(vulnerability, pipeline, policy_dismissals).to_json
  end

  def vulnerability_details(vulnerability, pipeline, policy_dismissals)
    return unless vulnerability

    result = {
      timestamp: Time.now.to_i,
      new_issue_url: new_issue_url_for(vulnerability),
      create_jira_issue_url: create_jira_issue_url_for(vulnerability),
      related_jira_issues_path: project_integrations_jira_issues_path(vulnerability.project, state: 'all', vulnerability_ids: [vulnerability.id]),
      jira_integration_settings_path: edit_project_settings_integration_path(vulnerability.project, ::Integrations::Jira),
      create_mr_url: create_vulnerability_feedback_merge_request_path(vulnerability.finding.project),
      discussions_url: discussions_project_security_vulnerability_path(vulnerability.project, vulnerability),
      notes_url: project_security_vulnerability_notes_path(vulnerability.project, vulnerability),
      related_issues_help_path: help_page_path('user/application_security/vulnerabilities/_index.md', anchor: 'linking-a-vulnerability-to-gitlab-and-jira-issues'),
      pipeline: vulnerability_pipeline_data(pipeline),
      can_modify_related_issues: Ability.allowed?(current_user, :admin_vulnerability_issue_link, vulnerability),
      can_admin: Ability.allowed?(current_user, :admin_vulnerability, vulnerability.project),
      can_create_security_ai_flow_feedback: Ability.allowed?(current_user, :create_security_ai_flow_feedback, vulnerability.project),
      can_update_vulnerability_severity: Ability.allowed?(current_user, :update_vulnerability_severity, vulnerability.project),
      can_confirm_vulnerability: Ability.allowed?(current_user, :confirm_vulnerability, vulnerability.project),
      can_resolve_vulnerability: Ability.allowed?(current_user, :resolve_vulnerability, vulnerability.project),
      can_revert_vulnerability: Ability.allowed?(current_user, :revert_vulnerability, vulnerability.project),
      can_dismiss_vulnerability: Ability.allowed?(current_user, :dismiss_vulnerability, vulnerability.project),
      dismissal_descriptions: dismissal_descriptions,
      representation_information: format_vulnerability_representation_information(vulnerability.representation_information),
      severity_override: severity_override_data(vulnerability),
      archival_information: archival_information(vulnerability),
      policy_dismissals: serialize_policy_dismissals(policy_dismissals),
      ascp_component: ascp_component_data(vulnerability),
      tracked_ref: tracked_ref_data(vulnerability),
      due_date: due_date_data(vulnerability)
    }

    result.merge(vulnerability_data(vulnerability), vulnerability_finding_data(vulnerability))
  end

  def due_date_data(vulnerability)
    vulnerability.finding.finding_due_date&.due_date
  end

  def archival_information(vulnerability)
    {
      about_to_be_archived: vulnerability.about_to_be_archived?,
      expected_to_be_archived_on: vulnerability.expected_to_be_archived_on
    }
  end

  def dismissal_descriptions
    Vulnerabilities::DismissalReasonEnum.translated_descriptions
  end

  def severity_override_data(vulnerability)
    severity_override = vulnerability.severity_overrides.last
    return unless severity_override

    {
      id: severity_override.id,
      original_severity: severity_override.original_severity,
      new_severity: severity_override.new_severity,
      author: {
        name: severity_override.author.name,
        web_url: user_path(severity_override.author)
      },
      created_at: severity_override.created_at
    }
  end

  def new_issue_url_for(vulnerability)
    return unless vulnerability.project.issues_enabled?

    new_project_issue_path(vulnerability.project, { vulnerability_id: vulnerability.id })
  end

  # This method can be called with an instance of the following models;
  # - Vulnerability
  # - Vulnerabilities::Finding
  # - Security::Finding
  #
  def create_jira_issue_url_for(vulnerability)
    return unless vulnerability.project.jira_integration&.configured_to_create_issues_from_vulnerabilities?

    decorated_vulnerability = vulnerability.present
    summary = _('Investigate vulnerability: %{title}') % { title: decorated_vulnerability.title }
    description = ApplicationController.render(
      template: 'vulnerabilities/jira_issue_description',
      formats: :md,
      locals: { vulnerability: decorated_vulnerability }
    )

    vulnerability.project.jira_integration.new_issue_url_with_predefined_fields(summary, description)
  end

  def vulnerability_pipeline_data(pipeline)
    return unless pipeline

    {
      id: pipeline.id,
      created_at: pipeline.created_at.iso8601,
      url: pipeline_path(pipeline),
      source_branch: pipeline.ref
    }
  end

  def vulnerability_data(vulnerability)
    VulnerabilitySerializer.new.represent(vulnerability)
  end

  def format_vulnerability_representation_information(representation_information)
    return unless representation_information

    {
      resolved_in_commit_sha: representation_information.resolved_in_commit_sha,
      resolved_in_commit_sha_link: resolved_in_commit_sha_link(representation_information),
      created_at: representation_information.created_at
    }
  end

  def resolved_in_commit_sha_link(representation_information)
    return unless representation_information&.resolved_in_commit_sha

    commit_path_template(representation_information.project).gsub('$COMMIT_SHA', representation_information.resolved_in_commit_sha)
  end

  def vulnerability_finding_data(vulnerability)
    finding = vulnerability.finding

    data = Vulnerabilities::FindingSerializer.new(current_user: current_user).represent(finding, only: FINDING_FIELDS)
    data[:location].merge!('blob_path' => vulnerability.blob_path).compact!
    data[:secret_redacted] = finding.secret_redacted?
    data[:description_html] = markdown(vulnerability.present.description)
    data[:solution_html] = markdown(vulnerability.present.solution)
    data[:ai_explanation_available] = finding.ai_explanation_available?
    data[:ai_resolution_available] = finding.ai_resolution_available?
    data[:belongs_to_public_project] = vulnerability.project.public?
    data[:cve_enrichment] = cve_enrichment(finding)
    data[:cvss] = cvss(vulnerability)
    if finding.project.security_setting&.validity_checks_enabled
      data[:finding_token_status] = finding.finding_token_status
    end

    data[:validity_checks_enabled] = finding.project&.security_setting&.validity_checks_enabled || false

    latest_flag_record = finding.latest_flag
    data[:latest_flag] = nil
    if latest_flag_record
      data[:latest_flag] = {
        id: latest_flag_record.id,
        description: latest_flag_record.description,
        confidence_score: latest_flag_record.confidence_score,
        origin: latest_flag_record.origin,
        status: latest_flag_record.status&.upcase
      }
    end

    data
  end

  def cve_enrichment(finding)
    return unless finding.cve_enrichment

    {
      epss_score: finding.cve_enrichment.epss_score,
      is_known_exploit: finding.cve_enrichment.is_known_exploit
    }
  end

  def cvss(vulnerability)
    vulnerability.cvss.filter_map do |data|
      cvss = CvssSuite.new(data['vector'])

      next unless cvss.valid?

      {
        overall_score: cvss.overall_score,
        version: cvss.version
      }
    end
  end

  def serialize_policy_dismissals(policy_dismissals)
    return [] unless policy_dismissals.present?

    Security::PolicyDismissalSerializer.new(current_user: current_user).represent(policy_dismissals)
  end

  def ascp_component_data(vulnerability)
    return unless Feature.enabled?(:vulnerability_ascp_security_context, vulnerability.project)
    return unless Ability.allowed?(current_user, :read_ascp_security_context, vulnerability.project)

    component = vulnerability.finding.ascp_component
    return unless component

    {
      id: component.id,
      security_context: ascp_security_context_data(component.security_context)
    }
  end

  def ascp_security_context_data(security_context)
    return unless security_context

    {
      id: security_context.id,
      authentication_model: security_context.authentication_model,
      authorization_model: security_context.authorization_model,
      data_sensitivity: security_context.data_sensitivity,
      security_boundary: security_context.security_boundary
    }
  end

  def tracked_ref_data(vulnerability)
    return unless ::Security::VAC.enabled?(vulnerability.project)
    return unless Ability.allowed?(current_user, :read_security_project_tracked_ref, vulnerability.project)

    tracked_context = vulnerability.vulnerability_read&.tracked_context
    return unless tracked_context

    {
      id: tracked_context.id,
      name: tracked_context.context_name,
      ref_type: tracked_context.context_type
    }
  end

  def vulnerability_scan_data?(vulnerability)
    vulnerability.scanner.present? || vulnerability.scan.present?
  end

  def vulnerabilities_export_download_url(export)
    expose_url(api_v4_security_vulnerability_exports_download_path(id: export.id))
  end

  def vulnerabilities_exportable_link(export)
    exportable = export.exportable

    if exportable.is_a?(InstanceSecurityDashboard)
      return link_to(s_('Vulnerabilities|Your personal dashboard'), security_dashboard_url)
    end

    link_text = exportable.full_name

    url = Gitlab::UrlBuilder.build(exportable)

    link_to(link_text, url)
  end
end
