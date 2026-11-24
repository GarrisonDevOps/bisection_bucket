# frozen_string_literal: true

module EE
  module Projects
    module Settings
      module CiCdController
        include ::API::Helpers::RelatedResourcesHelpers
        extend ::Gitlab::Utils::Override
        extend ActiveSupport::Concern

        prepended do
          before_action :assign_variables_to_gon, only: [:show]
          before_action :define_protected_env_variables, only: [:show]
          before_action :disable_query_limiting_for_show, only: [:show]
        end

        override :show
        def show
          if project.feature_available?(:license_scanning)
            @license_management_url = expose_url(api_v4_projects_managed_licenses_path(id: @project.id))
          end

          super
        end

        override :permitted_project_params
        def permitted_project_params
          attrs = %i[
            allow_pipeline_trigger_approve_deployment
          ]
          attrs << :restrict_pipeline_cancellation_role if @project.ci_cancellation_restriction.feature_available?

          super + attrs
        end

        override :permitted_project_ci_cd_settings_params
        def permitted_project_ci_cd_settings_params
          super + [:allow_composite_identities_to_run_pipelines]
        end

        private

        def define_protected_env_variables
          @protected_environments = @project.protected_environments.with_environment_id.sorted_by_name
          @protected_environment = ProtectedEnvironment.new(project: @project)
          # ignoring Layout/LineLength because if we break this into multiple lines, we cause Style/GuardClause errors
          @group_protected_environments = ProtectedEnvironment.for_groups(@project.group.self_and_ancestor_ids) if @project.group # rubocop:disable Layout/LineLength, Lint/RedundantCopDisableDirective
        end

        def assign_variables_to_gon
          gon.push(current_project_id: project.id)
          gon.push(deploy_access_levels: environment_dropdown.roles_hash)
          gon.push(search_unprotected_environments_url: search_project_protected_environments_path(@project))
        end

        def environment_dropdown
          @environment_dropdown ||= ProtectedEnvironments::EnvironmentDropdownService.new(project)
        end

        def disable_query_limiting_for_show
          # The AI sidebar evaluates ai_catalog_available? which calls StageCheck.available? ->
          # root_ancestor for projects in nested groups, adding 1 query beyond the FOSS baseline.
          # ProjectPolicy#foundational_flows_available? reads the cascading duo_foundational_flows_enabled
          # setting, which fires up to 2 extra queries (locked ancestor check + ancestor chain traversal)
          # when the value is not explicitly set at the project level.
          ::Gitlab::QueryLimiting.disable!(
            'https://gitlab.com/gitlab-org/gitlab/-/work_items/597397',
            new_threshold: 103
          )
        end
      end
    end
  end
end
