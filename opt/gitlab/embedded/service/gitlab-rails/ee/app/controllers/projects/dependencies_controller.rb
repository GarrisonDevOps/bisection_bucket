# frozen_string_literal: true

module Projects
  class DependenciesController < Projects::ApplicationController
    include SecurityAndCompliancePermissions
    include GovernUsageProjectTracking
    include Gitlab::InternalEventsTracking

    before_action only: :index do
      push_frontend_feature_flag(:dependency_paths, project)
      push_frontend_feature_flag(:vulnerabilities_across_contexts, project.root_namespace, type: :beta)
      push_frontend_feature_flag(:project_dependency_tracked_ref, project, type: :wip)
      push_frontend_ability(ability: :read_advanced_dependency_management, resource: project, user: current_user)
    end

    before_action :authorize_read_dependency_list!
    before_action :validate_component_versions!, only: :index

    feature_category :dependency_management
    urgency :low
    track_govern_activity 'dependencies', :index

    COMPONENT_NAMES_LIMIT_FOR_VERSION_FILTERING = 1

    def index
      respond_to do |format|
        format.html do
          track_internal_event(
            "visit_dependency_list",
            user: current_user,
            project: project
          )
          render status: :ok
        end
        format.json do
          track_internal_event(
            "called_dependency_api",
            user: current_user,
            project: project,
            additional_properties: {
              label: 'json'
            }
          )
          render json: serializer.represent(dependencies)
        end
      end
    end

    # This endpoint is being replaced by the `spdxLicenses` GraphQL query.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/600706
    def licenses
      render json: ::Sbom::DependencyLicenseListEntity.represent(
        Gitlab::SPDX::Catalogue.latest_licenses
      )
    end

    private

    def collect_dependencies
      dependencies_finder.execute
        .with_component
        .with_version
        .with_source
        .with_dependency_paths_existence
        .with_vulnerabilities_vulnerability_reads_and_project
    end

    def authorize_read_dependency_list!
      render_not_authorized unless can?(current_user, :read_dependency, project)
    end

    def dependencies
      @dependencies ||= collect_dependencies
    end

    def dependency_list_params
      params.permit(
        :filter,
        :page,
        :per_page,
        :sort,
        :sort_by,
        licenses: [],
        package_managers: [],
        component_names: [],
        source_types: [],
        component_versions: [],
        not: { component_versions: [] }
      ).with_defaults(source_types: default_source_type_filters)
    end

    def default_source_type_filters
      ::Sbom::Source::DEFAULT_SOURCES.keys + [nil]
    end

    def serializer
      ::DependencyListSerializer.new(
        project: project,
        user: current_user,
        license_override_applicator: project_license_override_applicator
      ).with_pagination(request, response)
    end

    def project_license_override_applicator
      @project_license_override_applicator ||= ::Security::LicenseOverrideApplicator.new(project)
    end

    def dependencies_finder
      ::Sbom::DependenciesFinder.new(project, params: dependency_list_params)
    end

    def render_not_authorized
      respond_to do |format|
        format.html do
          render_404
        end
        format.json do
          render_403
        end
      end
    end

    def validate_component_versions!
      return unless dependency_list_params[:component_versions] ||
        dependency_list_params.dig(:not, :component_versions)

      if dependency_list_params.fetch(:component_names, [])
        .size == COMPONENT_NAMES_LIMIT_FOR_VERSION_FILTERING
        track_internal_event(
          "filter_dependency_list_by_version",
          user: current_user,
          project: project
        )
      else
        render_error(
          :unprocessable_entity,
          format(_('Single component can be selected for component filter to be able to filter by version.'))
        )
      end
    end

    def render_error(status, message)
      respond_to do |format|
        format.json do
          render json: { message: message }, status: status
        end
      end
    end
  end
end
