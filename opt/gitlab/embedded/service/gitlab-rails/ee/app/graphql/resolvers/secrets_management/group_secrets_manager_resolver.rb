# frozen_string_literal: true

module Resolvers
  module SecretsManagement
    class GroupSecretsManagerResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource
      include ResolvesGroup
      include ::SecretsManagement::ResolverErrorHandling

      type ::Types::SecretsManagement::GroupSecretsManagerType, null: true

      argument :group_path, GraphQL::Types::ID,
        required: true,
        description: 'Group of the secrets manager.'

      authorize :read_group_secrets_manager_status

      def resolve(group_path:)
        group = authorized_find!(group_path: group_path)
        sm = group.secrets_manager&.refreshed_after_activation
        return sm if sm

        # SM row may have been deleted while OpenBao cleanup is still
        # in flight (trigger-based deprovision; gitlab-org/gitlab#600290).
        # Surface a phantom SM record so the caller sees the
        # DEPROVISIONING state from the pending maintenance task instead
        # of "no secrets manager".
        return unless ::SecretsManagement::GroupSecretsManagerMaintenanceTask.deprovision_pending_for?(group.id)

        ::SecretsManagement::GroupSecretsManager.new(
          group: group,
          status: ::SecretsManagement::GroupSecretsManager::STATUSES[:deprovisioning]
        )
      end

      private

      def find_object(group_path:)
        resolve_group(full_path: group_path)
      end
    end
  end
end
