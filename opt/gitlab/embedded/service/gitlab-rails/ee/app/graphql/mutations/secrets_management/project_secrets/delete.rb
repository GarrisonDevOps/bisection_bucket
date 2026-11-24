# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module ProjectSecrets
      class Delete < BaseMutation
        graphql_name 'ProjectSecretDelete'
        include ResolvesProject
        include Gitlab::InternalEventsTracking
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace

        authorize :delete_project_secrets
        authorize_granular_token permissions: :delete_secret,
          boundary_argument: :project_path, boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Project of the secret.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the project secret.'

        field :project_secret,
          Types::SecretsManagement::ProjectSecretType,
          null: true,
          description: "Deleted project secret."

        def resolve(project_path:, name:)
          project = authorized_find!(project_path: project_path)
          raise_if_namespace_inactive!(project)

          result = ::SecretsManagement::ProjectSecrets::DeleteService
            .new(project, current_user)
            .execute(name)

          if result.success?
            track_secret_deletion_event(project)
            {
              project_secret: result.payload[:secret],
              errors: []
            }
          elsif result.reason == :not_found
            raise_resource_not_available_error!("Project secret does not exist.")
          else
            {
              project_secret: nil,
              errors: [result.message]
            }
          end
        end

        private

        def find_object(project_path:)
          resolve_project(full_path: project_path)
        end

        def track_secret_deletion_event(project)
          track_internal_event(
            'delete_project_ci_secret',
            user: current_user,
            namespace: project.namespace,
            project: project
          )
        end
      end
    end
  end
end
