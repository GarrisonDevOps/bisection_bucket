# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class ProjectSecretsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ResolvesProject
      include ::SecretsManagement::ResolverErrorHandling

      type [::Types::SecretsManagement::ProjectSecretType], null: true
      extras [:lookahead]

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Project the secrets belong to.'

      authorize :read_project_secrets

      def resolve(lookahead:, project_path:)
        project = authorized_find!(project_path: project_path)

        result = ::SecretsManagement::ProjectSecrets::ListService.new(
          project,
          current_user
        ).execute(include_rotation_info: include_rotation_info?(lookahead))

        if result.success?
          result.payload[:secrets]
        else
          raise_resource_not_available_error!(result.message)
        end
      end

      private

      def include_rotation_info?(lookahead)
        lookahead.selection(:nodes).selects?(:rotation_info) ||
          lookahead.selection(:edges).selection(:node).selects?(:rotation_info)
      end

      def find_object(project_path:)
        resolve_project(full_path: project_path)
      end
    end
  end
end
