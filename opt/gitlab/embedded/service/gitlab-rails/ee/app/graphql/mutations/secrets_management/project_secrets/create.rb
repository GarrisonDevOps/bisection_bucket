# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module ProjectSecrets
      class Create < BaseMutation
        graphql_name 'ProjectSecretCreate'

        include ResolvesProject
        include Gitlab::InternalEventsTracking
        include Helpers::ErrorMessagesHelpers
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :project_secret, find_by: :project_path

        authorize :create_project_secrets
        authorize_granular_token permissions: :create_secret,
          boundary_argument: :project_path, boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Project of the secret.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the project secret.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'Description of the project secret.'

        argument :secret, GraphQL::Types::String,
          required: true,
          description: 'Value of the project secret.'

        argument :environment, GraphQL::Types::String,
          required: true,
          description: 'Environments that can access the secret.'

        argument :branch, GraphQL::Types::String,
          required: true,
          description: 'Branches that can access the secret.'

        argument :rotation_interval_days, GraphQL::Types::Int,
          required: false,
          description: 'Number of days between rotation reminders for the secret.'

        field :project_secret,
          Types::SecretsManagement::ProjectSecretType,
          null: true,
          description: "Project secret."

        def resolve(project_path:, name:, secret:, environment:, branch:, description: nil, rotation_interval_days: nil)
          project = authorized_find!(project_path: project_path)
          raise_if_namespace_inactive!(project)

          result = ::SecretsManagement::ProjectSecrets::CreateService
            .new(project, current_user)
            .execute(
              name: name,
              description: description,
              value: secret,
              environment: environment,
              branch: branch,
              rotation_interval_days: rotation_interval_days
            )

          if result.success?
            track_secret_creation_event(project)
            {
              project_secret: result.payload[:secret],
              errors: []
            }
          else
            {
              project_secret: nil,
              errors: error_messages(result, [:secret])
            }
          end
        end

        private

        def find_object(project_path:)
          resolve_project(full_path: project_path)
        end

        def track_secret_creation_event(project)
          track_internal_event(
            'create_ci_secret',
            user: current_user,
            namespace: project.namespace,
            project: project
          )
        end
      end
    end
  end
end
