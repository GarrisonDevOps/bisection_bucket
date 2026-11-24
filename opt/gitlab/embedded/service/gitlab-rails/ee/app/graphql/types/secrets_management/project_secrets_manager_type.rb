# frozen_string_literal: true

module Types
  module SecretsManagement
    class ProjectSecretsManagerType < BaseObject
      graphql_name 'ProjectSecretsManager'
      description 'Representation of a project secrets manager.'

      authorize_granular_token permissions: :read_secrets_manager,
        boundary: :project, boundary_type: :project

      authorize :read_project_secrets_manager_status

      expose_permissions Types::PermissionTypes::SecretsManagement::ProjectSecretsManager

      field :project,
        Types::ProjectType,
        null: false,
        description: 'Project the secrets manager belong to.'

      # Resolved from `effective_status`, which reports `DEPROVISIONING`
      # whenever a deprovision maintenance task is pending for the
      # project, even if the underlying `status` column on the SM row
      # would otherwise say otherwise. This keeps the reported status
      # honest in the upcoming trigger-based deprovision flow
      # (gitlab-org/gitlab#600290) where the SM row may be deleted
      # before OpenBao cleanup completes.
      field :status,
        Types::SecretsManagement::ProjectSecretsManagerStatusEnum,
        method: :effective_status,
        description: 'Status of the project secrets manager.'

      field :read_only,
        GraphQL::Types::Boolean,
        null: false,
        experiment: { milestone: '19.4' },
        description: 'Whether the instance is in strict read-only mode (Geo secondary or maintenance mode). ' \
          'No secrets or permissions can be created, updated, or deleted while it is true.'

      field :write_denial_reason,
        Types::SecretsManagement::WriteActionDenialReasonEnum,
        null: true,
        experiment: { milestone: '19.5' },
        description: 'Reason the Secrets Manager entitlement does not allow secrets or their permissions ' \
          'to be created or updated. Null when it allows them.'

      def read_only
        ::Gitlab::Database.read_only?
      end

      def write_denial_reason
        project = object.project
        root_namespace = ::SecretsManagement::Entitlement.root_namespace_for(project)
        ::SecretsManagement::Entitlement.for(root_namespace, user: current_user).write_action_denial_reason
      end
    end
  end
end
