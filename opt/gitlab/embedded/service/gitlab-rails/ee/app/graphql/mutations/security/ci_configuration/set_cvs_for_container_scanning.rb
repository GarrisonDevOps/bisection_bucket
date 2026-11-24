# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class SetCvsForContainerScanning < BaseMutation
        graphql_name 'SetCvsForContainerScanning'

        include FindsProject

        description <<~DESC
          Enable or disable continuous vulnerability scanning for container scanning for the given project.
        DESC

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project.'

        argument :enable, GraphQL::Types::Boolean,
          required: true,
          description: 'Desired status for CVS for container scanning.'

        field :cvs_for_container_scanning_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether CVS for container scanning is enabled.'

        authorize :update_cvs_for_container_scanning

        authorize_granular_token permissions: :update_security_setting,
          boundary_argument: :project_path, boundary_type: :project

        def resolve(project_path:, enable:)
          project = authorized_find!(project_path)

          raise_resource_not_available_error! if project.self_or_ancestors_archived?

          response = ::Security::Configuration::SetCvsForScannerTypeService
            .execute(project: project, enable: enable, scanner_type: :container_scanning)

          { cvs_for_container_scanning_enabled: response.payload[:enabled], errors: response.errors }
        end
      end
    end
  end
end
