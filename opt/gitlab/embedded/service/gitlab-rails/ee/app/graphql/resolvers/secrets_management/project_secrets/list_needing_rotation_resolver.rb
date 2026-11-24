# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    module ProjectSecrets
      class ListNeedingRotationResolver < BaseResolver
        include Gitlab::Graphql::Authorize::AuthorizeResource
        include ResolvesProject
        include ::SecretsManagement::ResolverErrorHandling

        type [::Types::SecretsManagement::ProjectSecretType], null: true

        argument :project_path, GraphQL::Types::ID,
          required: true,
          description: 'Project the secrets belong to.'

        authorize :read_project_secrets

        def resolve(project_path:)
          project = authorized_find!(project_path: project_path)

          result = ::SecretsManagement::ProjectSecrets::ListNeedingRotationService.new(
            project,
            current_user
          ).execute

          if result.success?
            result.payload[:secrets]
          else
            raise_resource_not_available_error!(result.message)
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
