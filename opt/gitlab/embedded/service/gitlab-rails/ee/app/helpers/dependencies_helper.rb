# frozen_string_literal: true

module DependenciesHelper
  include API::Helpers::RelatedResourcesHelpers

  def project_dependencies_data(project)
    pipeline = project.latest_ingested_sbom_pipeline

    shared_dependencies_data.merge({
      has_dependencies: project.has_dependencies?.to_s,
      endpoint: project_dependencies_path(project, format: :json),
      licenses_endpoint: licenses_project_dependencies_path(project),
      export_endpoint: expose_path(api_v4_projects_dependency_list_exports_path(id: project.id)),
      sbom_reports_errors: sbom_report_ingestion_errors(pipeline).to_json,
      latest_successful_scan_path: (project_pipeline_path(project, pipeline) if pipeline),
      scan_finished_at: pipeline&.finished_at,
      project_full_path: project.full_path
    }).merge(security_dashboard_default_tracked_ref_data(project))
  end

  def group_dependencies_data(group)
    shared_dependencies_data.merge({
      has_dependencies: group.has_dependencies?.to_s,
      endpoint: group_dependencies_path(group, format: :json),
      licenses_endpoint: licenses_group_dependencies_path(group),
      locations_endpoint: locations_group_dependencies_path(group),
      export_endpoint: expose_path(api_v4_groups_dependency_list_exports_path(id: group.id)),
      group_full_path: group.full_path
    })
  end

  def dependencies_export_download_url(export)
    expose_url(api_v4_dependency_list_exports_download_path(export_id: export.id))
  end

  def dependencies_exportable_link(export)
    exportable = export.exportable

    link_text = case exportable
                when ::Project, ::Group
                  exportable.full_name
                when ::Organizations::Organization
                  exportable.name
                when ::Ci::Pipeline
                  "##{exportable.id}"
                end

    url = Gitlab::UrlBuilder.build(exportable)

    link_to(link_text, url)
  end

  private

  def shared_dependencies_data
    {
      documentation_path: help_page_path('user/application_security/dependency_list/_index.md'),
      empty_state_svg_path: image_path('illustrations/empty-state/empty-radar-md.svg')
    }
  end

  def sbom_report_ingestion_errors(pipeline)
    pipeline&.sbom_report_ingestion_errors || []
  end
end
