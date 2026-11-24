# frozen_string_literal: true

module Mutations
  module SecretsManagement
    module ProjectSecrets
      class Update < BaseMutation
        graphql_name 'ProjectSecretUpdate'

        include Helpers::ErrorMessagesHelpers
        include Gitlab::InternalEventsTracking
        include ResolvesProject
        include ::SecretsManagement::MutationErrorHandling
        include ::SecretsManagement::RequiresActiveNamespace
        include ::SecretsManagement::EnforcesWriteEntitlement

        enforces_write_entitlement_for :project_secret, find_by: :project_path

        authorize :update_project_secrets
        authorize_granular_token permissions: :update_secret,
          boundary_argument: :project_path, boundary_type: :project

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Project of the secret.'

        argument :name, GraphQL::Types::String,
          required: true,
          description: 'Name of the project secret to update.'

        argument :description, GraphQL::Types::String,
          required: false,
          description: 'New description of the project secret.'

        argument :secret, GraphQL::Types::String,
          required: false,
          description: 'New value of the project secret.'

        argument :environment, GraphQL::Types::String,
          required: false,
          description: 'New environments that can access the secret.'

        argument :branch, GraphQL::Types::String,
          required: false,
          description: 'New branches that can access the secret.'

        argument :rotation_interval_days, GraphQL::Types::Int,
          required: false,
          description: 'Number of days between rotation reminders for the secret.'

        argument :metadata_cas, GraphQL::Types::Int,
          required: true,
          description: 'This should match the current metadata version of the project secret being updated.'

        field :project_secret,
          Types::SecretsManagement::ProjectSecretType,
          null: true,
          description: "Updated project secret."

        def resolve(project_path:, name:, **args)
          project = authorized_find!(project_path: project_path)
          raise_if_namespace_inactive!(project)

          result = ::SecretsManagement::ProjectSecrets::UpdateService
            .new(project, current_user)
            .execute(
              name: name,
              description: args[:description],
              value: args[:secret],
              environment: args[:environment],
              branch: args[:branch],
              metadata_cas: args[:metadata_cas],
              rotation_interval_days: args[:rotation_interval_days]
            )

          if result.success?
            track_secret_update_event(project)
            {
              project_secret: result.payload[:secret],
              errors: []
            }
          elsif result.reason == :not_found
            raise_resource_not_available_error!("Project secret does not exist.")
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

        def track_secret_update_event(project)
          track_internal_event(
            'update_ci_secret',
            user: current_user,
            namespace: project.namespace,
            project: project,
            additional_properties: {
              label: 'graphql'
            }
          )
        end
      end
    end
  end
end
