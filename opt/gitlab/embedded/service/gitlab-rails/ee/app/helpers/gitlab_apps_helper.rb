# frozen_string_literal: true

module GitlabAppsHelper
  # The layout passes in the resources the controller has already loaded and authorized; params would be
  # neither.
  #
  # @param project [Project, nil]
  # @param pipeline [Ci::Pipeline, nil]
  # @return [Hash{Symbol => Array<Hash>}] the apps of each mount point on the current page, each linked with
  #   the context that mount point offers. Mount points without apps are left out.
  def gitlab_apps_by_mount_point(project: nil, pipeline: nil)
    gitlab_app_mount_point_contexts(project: project, pipeline: pipeline).filter_map do |mount, (namespace, context)|
      apps = ::Gitlab::Apps.for(namespace, mount: mount).map do |app|
        app.to_nav_item.merge(link: ::Gitlab::Utils.add_url_parameters(app.url, context))
      end

      [mount, apps] if apps.any?
    end.to_h
  end

  private

  # Hardcoded for the PoC: the mount points each page offers, the namespace their flag check runs against,
  # and the context passed to their apps.
  def gitlab_app_mount_point_contexts(project:, pipeline:)
    case controller.controller_path
    when 'projects/pipelines'
      return {} unless project && pipeline&.persisted?

      { pipeline: [project, { gl_project_path: project.full_path, gl_pipeline_id: pipeline.id }] }
    else
      {}
    end
  end
end
