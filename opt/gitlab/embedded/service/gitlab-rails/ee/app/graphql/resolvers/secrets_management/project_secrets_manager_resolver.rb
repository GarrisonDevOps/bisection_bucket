# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class ProjectSecretsManagerResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ResolvesProject
      include ::SecretsManagement::ResolverErrorHandling

      type ::Types::SecretsManagement::ProjectSecretsManagerType, null: true

      argument :project_path, GraphQL::Types::ID,
        required: true,
        description: 'Project of the secrets manager.'

      authorize :read_project_secrets_manager_status

      def resolve(project_path:)
        project = authorized_find!(project_path: project_path)
        sm = project.secrets_manager&.refreshed_after_activation
        return sm if sm

        # SM row may have been deleted while OpenBao cleanup is still
        # in flight (trigger-based deprovision; gitlab-org/gitlab#600290).
        # Surface a phantom SM record so the caller sees the
        # DEPROVISIONING state from the pending maintenance task instead
        # of "no secrets manager".
        return unless ::SecretsManagement::ProjectSecretsManagerMaintenanceTask.deprovision_pending_for?(project.id)

        ::SecretsManagement::ProjectSecretsManager.new(
          project: project,
          status: ::SecretsManagement::ProjectSecretsManager::STATUSES[:deprovisioning]
        )
      end

      private

      def find_object(project_path:)
        resolve_project(full_path: project_path)
      end
    end
  end
end
