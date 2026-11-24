# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class ConfigureDependencyScanning < BaseSecurityAnalyzer
        graphql_name 'ConfigureDependencyScanning'

        authorize_granular_token permissions: [:push_code, :create_branch],
          boundary_argument: :project_path, boundary_type: :project
        description <<~DESC
          Enable dependency scanning `.gitlab-ci.yml` file in a new branch.
          The new branch and a URL to create a merge request are a part of
          the response.
        DESC

        def configure_analyzer(project, **_args)
          ::Security::CiConfiguration::DependencyScanningCreateService.new(project, current_user).execute
        end
      end
    end
  end
end
