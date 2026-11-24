# frozen_string_literal: true

module API
  class Dependencies < ::API::Base
    include PaginationParams

    feature_category :dependency_management
    urgency :low

    helpers do
      def dependencies_by(params)
        project = params[:project]
        params[:package_managers] = params.delete(:package_manager)
        dependencies = ::Sbom::DependenciesFinder.new(project, params: params).execute.with_component.with_version
        dependencies = dependencies.with_vulnerabilities if params[:preload_vulnerabilities]
        dependencies
      end
    end

    before { authenticate! }

    params do
      requires :id, types: [String, Integer], desc: 'ID or URL-encoded path of the project.'
    end

    resource :projects, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
      desc 'List all project dependencies' do
        detail 'Lists all dependencies for a specified project. This operation partially mirrors the dependency list ' \
          'feature, which is available only for languages and package managers supported by Gemnasium. Responses are ' \
          'paginated and return 20 results by default.'
        success code: 200, model: ::API::Entities::Dependency
        is_array true
        failure [{ code: 401, message: 'Unauthorized' }, { code: 404, message: 'Not found' }]
        tags ['dependency_management']
      end

      params do
        optional :package_manager,
          type: Array[String],
          coerce_with: Validations::Types::CommaSeparatedToArray.coerce,
          desc: 'Filter results by the specified package manager.',
          values: ::Sbom::DependenciesFinder::FILTER_PACKAGE_MANAGERS_VALUES,
          documentation: { example: %w[maven yarn] }
        use :pagination
      end

      route_setting :tier, :ultimate
      route_setting :authorization, permissions: :read_dependency, boundary_type: :project
      get ':id/dependencies' do
        authorize! :read_dependency, user_project

        ::Gitlab::Tracking.event(self.options[:for].name, 'view_dependencies', project: user_project, user: current_user, namespace: user_project.namespace)

        can_read_vulnerabilities = Ability.allowed?(current_user, :read_vulnerability, user_project)
        dependency_params = declared_params(include_missing: false)
          .merge(
            project: user_project,
            preload_vulnerabilities: can_read_vulnerabilities
          )
        dependencies = paginate(dependencies_by(dependency_params))
        dependencies = dependencies.with_vulnerabilities_vulnerability_reads_and_project if can_read_vulnerabilities

        # Mirrors the conditions under which API::Entities::Dependency renders `malware`, so a
        # response that omits the field does not pay for resolving it.
        if Ability.allowed?(current_user, :read_security_resource, user_project)
          ::Sbom::MalwareAdvisoriesPreloader.new(dependencies.to_a).execute
        end

        present dependencies, with: ::API::Entities::Dependency, user: current_user, project: user_project
      end
    end
  end
end
