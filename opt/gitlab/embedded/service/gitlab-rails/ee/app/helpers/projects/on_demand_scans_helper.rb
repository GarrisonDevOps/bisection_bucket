# frozen_string_literal: true

module Projects::OnDemandScansHelper
  def on_demand_scans_data(current_user, project)
    pipelines_counter = Gitlab::PipelineScopeCounts.new(current_user, project, {
      source: "ondemand_dast_scan"
    })
    scheduled_scans_count = ::Dast::ProfilesFinder.new({ project_id: project.id, has_dast_profile_schedule: true }).execute.count
    saved_scans_count = ::Dast::ProfilesFinder.new({ project_id: project.id }).execute.count

    common_data(project).merge({
      'project-on-demand-scan-counts-etag' => graphql_etag_project_on_demand_scan_counts_path(project),
      'on-demand-scan-counts' => {
        all: pipelines_counter.all,
        running: pipelines_counter.running,
        finished: pipelines_counter.finished,
        scheduled: scheduled_scans_count,
        saved: saved_scans_count
      }.to_json,
      'new-dast-scan-path' => new_project_on_demand_scan_path(project),
      'empty-state-svg-path' => image_path('illustrations/empty-state/empty-radar-md.svg'),
      'timezones' => timezone_data(format: :abbr).to_json,
      'can-edit-on-demand-scans' => can?(current_user, :edit_on_demand_dast_scan, project).to_s
    })
  end

  def on_demand_scans_form_data(project)
    common_data(project).merge({
      'default-branch' => project.default_branch,
      'on-demand-scans-path' => project_on_demand_scans_path(project, anchor: 'saved'),
      'scanner-profiles-library-path' => project_security_configuration_profile_library_path(project, anchor: 'scanner-profiles'),
      'site-profiles-library-path' => project_security_configuration_profile_library_path(project, anchor: 'site-profiles'),
      'timezones' => timezone_data(format: :full).to_json,
      'additional-variable-options' => Gitlab::Security::DastVariables.additional_site_variables.to_json,
      'can_read_runners' => Ability.allowed?(current_user, :read_runners, project).to_s
    })
  end

  private

  def common_data(project)
    {
      'project-path' => project.path_with_namespace
    }
  end
end
