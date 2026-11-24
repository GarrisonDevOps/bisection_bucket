# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class ProjectSecretsCountResolver < BaseResolver
      include ::SecretsManagement::ResolverErrorHandling

      type GraphQL::Types::Int, null: true

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Full path of the project.'

      def resolve(project_path:)
        project = Project.find_by_full_path(project_path)

        # secrets count is fetched by the project delete modal
        # some authorization access errors are due to feature flags
        # so we should return null in this case
        return unless Ability.allowed?(current_user, :read_project_secrets, project)
        return unless project.secrets_manager&.active_after_refresh?

        ::SecretsManagement::ProjectSecretsCountService.new(project, current_user).execute
      end
    end
  end
end
