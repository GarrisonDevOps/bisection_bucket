# frozen_string_literal: true

module SecretsManagement
  module Secrets
    module DeleteServiceHelpers
      def execute_secret_deletion(resource:, name:)
        with_exclusive_lease_for(resource) do
          delete_secret(name)
        end
      end

      def delete_secret(name)
        return secrets_manager_inactive_response unless secrets_manager&.active_after_refresh?

        read_result = read_secret(name)
        return read_result unless read_result.success?

        secret = read_result.payload[:secret]

        user_client.delete_kv_secret(
          secrets_manager.ci_secrets_mount_path,
          secrets_manager.ci_data_path(name)
        )

        refresh_secret_ci_policies(secret, delete_operation: true)

        enqueue_namespace_secret_count_refresh

        ServiceResponse.success(payload: { secret: secret })
      end

      private

      def enqueue_namespace_secret_count_refresh
        namespace_id = secrets_manager&.namespace_id_for_secret_count
        return unless namespace_id

        ReconcileNamespaceSecretCountWorker.perform_async(namespace_id, current_user&.id)
      end
    end
  end
end
