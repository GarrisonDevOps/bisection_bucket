# frozen_string_literal: true

module Groups
  class DependenciesController < Groups::ApplicationController
    include GovernUsageGroupTracking
    include Gitlab::InternalEventsTracking
    include ::Sbom::OccurrenceRefsFilterable

    before_action only: :index do
      push_frontend_feature_flag(:dependency_paths, group)
      push_frontend_feature_flag(:group_dependencies_graphql, group)
      push_frontend_ability(ability: :read_advanced_dependency_management, resource: group, user: current_user)
    end

    before_action :authorize_read_dependency_list!
    before_action :validate_project_ids_limit!, only: :index
    before_action :validate_component_versions!, only: :index

    feature_category :dependency_management
    urgency :low
    track_govern_activity 'dependencies', :index

    PROJECT_IDS_LIMIT = 10
    COMPONENT_NAMES_LIMIT_FOR_VERSION_FILTERING = 1

    rescue_from ::Search::Elastic::CompositePagination::Paginator::InvalidCursorError do |error|
      render_error(:bad_request, error.message)
    end

    def index
      respond_to do |format|
        format.html do
          track_internal_event(
            "visit_dependency_list",
            user: current_user,
            namespace: group
          )
          render status: :ok
        end
        format.json do
          track_internal_event(
            "called_dependency_api",
            user: current_user,
            namespace: group,
            additional_properties: {
              label: 'json'
            }
          )

          preload_policy_dismissals! if can?(current_user, :read_security_resource, group)

          render json: dependencies_serializer.represent(materialized_dependencies)
        end
      end
    end

    def locations
      render json: ::Sbom::DependencyLocationListEntity.represent(
        Sbom::DependencyLocationsFinder.new(
          namespace: group,
          params: dependency_locations_params
        ).execute
        .with_dependency_paths_existence
      )
    end

    # This endpoint is being replaced by the `spdxLicenses` GraphQL query.
    # See https://gitlab.com/gitlab-org/gitlab/-/work_items/600706
    def licenses
      render json: ::Sbom::DependencyLicenseListEntity.represent(
        Gitlab::SPDX::Catalogue.latest_licenses
      )
    end

    private

    def authorize_read_dependency_list!
      return if can?(current_user, :read_dependency, group)

      render_not_authorized
    end

    def validate_project_ids_limit!
      return unless dependencies_finder_params.fetch(:project_ids, []).size > PROJECT_IDS_LIMIT

      render_error(
        :unprocessable_entity,
        format(_('A maximum of %{limit} projects can be searched for at one time.'), limit: PROJECT_IDS_LIMIT)
      )
    end

    def validate_component_versions!
      return unless dependencies_finder_params[:component_versions] ||
        dependencies_finder_params.dig(:not, :component_versions)

      if dependencies_finder_params.fetch(:component_names, []).size == COMPONENT_NAMES_LIMIT_FOR_VERSION_FILTERING
        track_internal_event(
          "filter_dependency_list_by_version",
          user: current_user,
          namespace: group
        )
      else
        render_error(
          :unprocessable_entity,
          format(_('Single component can be selected for component filter to be able to filter by version.'))
        )
      end
    end

    def dependencies
      @dependencies ||= if using_advanced_search?
                          advanced_search_dependencies
                        elsif has_project_ids?
                          postgres_per_occurrence_dependencies
                        else
                          postgres_aggregated_dependencies
                        end
    end

    def dependency_locations_params
      params.permit(:component_id, :search)
    end

    def advanced_search_dependencies
      paginator = ::Search::Elastic::CompositePagination::Paginator.new(
        finder: ::Search::AdvancedFinders::Sbom::AggregationsFinder,
        source: group,
        params: advanced_search_finder_params,
        cursor: params.permit(:cursor)[:cursor],
        per_page: per_page
      )

      apply_pagination_headers!(paginator)

      paginator.records
    end

    def postgres_aggregated_dependencies
      finder = ::Sbom::AggregationsFinder.new(group, params: dependencies_finder_params)
      relation = finder.execute
                       .with_component
                       .with_version

      paginator = Gitlab::Pagination::Keyset::Paginator.new(
        scope: relation.dup,
        cursor: dependencies_finder_params[:cursor],
        per_page: per_page
      )

      apply_pagination_headers!(paginator)

      relation
    end

    def postgres_per_occurrence_dependencies
      ::Sbom::DependenciesFinder
        .new(group, params: dependencies_finder_params).execute
        .with_component
        .with_version
        .with_source
        .with_project_route
    end

    def advanced_search_finder_params
      dependencies_finder_params.to_h.merge(malware: ::Gitlab::Utils.to_boolean(params.permit(:malware)[:malware]))
    end

    def dependencies_finder_params
      params.permit(
        :cursor,
        :malware,
        :page,
        :per_page,
        :sort,
        :sort_by,
        licenses: [],
        package_managers: [],
        project_ids: [],
        component_ids: [],
        component_names: [],
        component_versions: [],
        not: { component_versions: [] }
      )
    end
    strong_memoize_attr :dependencies_finder_params

    def dependencies_serializer
      serializer = DependencyListSerializer.new(
        project: nil,
        group: group,
        user: current_user,
        license_override_applicator: group_license_override_applicator
      )
      serializer = serializer.with_pagination(request, response) unless aggregated_query?
      serializer
    end

    def group_license_override_applicator
      # new_for_group already checks the feature flag and returns NULL_APPLICATOR when disabled.
      @group_license_override_applicator ||= ::Security::LicenseOverrideApplicator.new_for_group(group)
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

    def render_error(status, message)
      respond_to do |format|
        format.json do
          render json: { message: message }, status: status
        end
      end
    end

    def apply_pagination_headers!(paginator)
      response.header['X-Next-Page'] = paginator.cursor_for_next_page
      response.header['X-Page'] = dependencies_finder_params[:cursor]
      response.header['X-Page-Type'] = 'cursor'
      response.header['X-Prev-Page'] = paginator.cursor_for_previous_page
      response.header['X-Per-Page'] = per_page
    end

    def per_page
      dependencies_finder_params[:per_page]&.to_i || Sbom::AggregationsFinder::DEFAULT_PAGE_SIZE
    end

    def has_project_ids?
      dependencies_finder_params[:project_ids].present?
    end

    def using_advanced_search?
      use_elasticsearch?(dependencies_finder_params)
    end

    # Both aggregating finders collapse a component version to one representative row and page
    # with an opaque cursor. ::Sbom::DependenciesFinder returns one row per occurrence.
    def aggregated_query?
      using_advanced_search? || !has_project_ids?
    end
    strong_memoize_attr :aggregated_query?

    def filterable_namespace
      group
    end

    def materialized_dependencies
      @materialized_dependencies ||= dependencies.to_a
    end

    def preload_policy_dismissals!
      ::Preloaders::Sbom::PolicyDismissalsPreloader.new(materialized_dependencies, group).execute
    end
  end
end
