# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class SetLicenseConfigurationSource < BaseMutation
        graphql_name 'SetLicenseConfigurationSource'

        include ResolvesProject

        description <<~DESC
          Set the license information source for a given project.
        DESC

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the project.'

        argument :source, ::Types::Security::PreferredLicenseSourceConfigurationEnum,
          required: true,
          description: 'Preferred source of license information for dependencies.'

        field :license_configuration_source, ::Types::Security::PreferredLicenseSourceConfigurationEnum,
          null: true,
          description: 'Preferred source of license information for dependencies.'

        authorize :set_license_information_source

        authorize_granular_token permissions: :update_security_setting,
          boundary_argument: :project_path, boundary_type: :project

        def resolve(project_path:, source:)
          project = authorized_find!(project_path: project_path)

          response = ::Security::Configuration::SetLicenseConfigurationSourceService
            .execute(project: project, source: source)

          { license_configuration_source: response.payload[:license_configuration_source], errors: response.errors }
        end

        def find_object(project_path:)
          resolve_project(full_path: project_path)
        end
      end
    end
  end
end
