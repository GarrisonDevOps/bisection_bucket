# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class SetLicenseScanningForCyclonedx < BaseMutation
        graphql_name 'SetLicenseScanningForCyclonedx'

        include FindsProject

        description <<~DESC
          Enable/disable license scanning for CycloneDX SBOM files for the given project.
        DESC

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project.'

        argument :enable, GraphQL::Types::Boolean,
          required: true,
          description: 'Desired status for license scanning for CycloneDX files.'

        field :license_scanning_for_cyclonedx_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether license scanning for CycloneDX files is enabled.'

        authorize :toggle_license_scanning_for_cyclonedx

        authorize_granular_token permissions: :update_security_setting,
          boundary_argument: :project_path, boundary_type: :project

        def resolve(project_path:, enable:)
          project = authorized_find!(project_path)

          raise_resource_not_available_error! if project.self_or_ancestors_archived?

          response = ::Security::Configuration::SetLicenseScanningForCyclonedxService
            .execute(namespace: project, enable: enable)

          { license_scanning_for_cyclonedx_enabled: response.payload[:enabled], errors: response.errors }
        end
      end
    end
  end
end
