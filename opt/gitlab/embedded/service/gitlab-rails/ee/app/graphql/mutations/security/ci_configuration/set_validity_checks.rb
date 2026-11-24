# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class SetValidityChecks < BaseMutation
        graphql_name 'SetValidityChecks'

        include ResolvesProject

        description <<~DESC
          Enable/disable secret detection validity checks for the given project.
        DESC

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the namespace (project).'

        argument :enable, GraphQL::Types::Boolean,
          required: true,
          description: 'Desired status for validity checks feature.'

        field :validity_checks_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether the feature is enabled.'

        authorize :update_secret_detection_validity_check

        authorize_granular_token permissions: :update_security_setting,
          boundary_argument: :namespace_path, boundary_type: :project

        def resolve(namespace_path:, enable:)
          project = authorized_find!(project_path: namespace_path)
          response = ::Security::Configuration::SetValidityChecksService
            .execute(current_user: current_user, project: project, enable: enable)

          { validity_checks_enabled: response.payload[:enabled], errors: response.errors }
        end

        private

        def find_object(project_path:)
          resolve_project(full_path: project_path)
        end
      end
    end
  end
end
