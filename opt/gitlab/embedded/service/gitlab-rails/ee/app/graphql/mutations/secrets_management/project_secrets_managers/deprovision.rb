# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module ProjectSecretsManagers
      class Deprovision < BaseMutation
        graphql_name 'ProjectSecretsManagerDeprovision'

        include ResolvesProject
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :project_secrets_manager, find_by: :project_path

        authorize :admin_project_secrets_manager
        authorize_granular_token permissions: :deprovision_secrets_manager,
          boundary_argument: :project_path, boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Project of the secrets manager.'

        field :project_secrets_manager,
          Types::SecretsManagement::ProjectSecretsManagerType,
          null: true,
          description: "Project secrets manager."

        def resolve(project_path:)
          project = authorized_find!(project_path: project_path)

          result = ::SecretsManagement::ProjectSecretsManagers::InitiateDeprovisionService.new(
            project.secrets_manager,
            current_user,
            project_id: project.id
          ).execute

          if result.success?
            {
              project_secrets_manager: result.payload[:project_secrets_manager],
              errors: []
            }
          else
            {
              project_secrets_manager: nil,
              errors: [result.message]
            }
          end
        end

        private

        def find_object(project_path:)
          resolve_project(full_path: project_path)
        end
      end
    end
  end
end
