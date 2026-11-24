# frozen_string_literal: true

module SecretsManagement
  module CiPolicies
    class BaseSecretRefresher
      def initialize(secrets_manager, secrets_manager_client)
        @secrets_manager = secrets_manager
        @secrets_manager_client = secrets_manager_client
      end

      def refresh_ci_policies_for(secret, delete_operation: false)
        policy_to_be_removed_from, policy_to_be_added_to = policies_to_transition(secret,
          delete_operation: delete_operation)

        if policy_to_be_removed_from
          should_delete = should_delete_policy?(policy_to_be_removed_from, secret: secret)
          remove_secret_from_policy(secret, policy_to_be_removed_from, delete_policy: should_delete)
        end

        add_read_secret_capabilities_to_policy(secret, policy_to_be_added_to) if policy_to_be_added_to
      end

      private

      attr_reader :secrets_manager, :secrets_manager_client

      def remove_secret_from_policy(secret, policy_name, delete_policy: false)
        if delete_policy
          secrets_manager_client.delete_policy(policy_name)
        else
          remove_read_secret_capabilities_from_policy(policy_name, secret.name)
        end
      end

      def remove_read_secret_capabilities_from_policy(policy_name, secret_name)
        policy = secrets_manager_client.get_policy(policy_name)
        policy.remove_capability(secrets_manager.ci_full_path(secret_name), "read")
        policy.remove_capability(secrets_manager.ci_metadata_full_path(secret_name), "read")
        secrets_manager_client.set_policy(policy)
      end

      def add_read_secret_capabilities_to_policy(secret, policy_name)
        policy = secrets_manager_client.get_policy(policy_name)
        policy.add_capability(
          secrets_manager.ci_full_path(secret.name),
          "read"
        )
        policy.add_capability(
          secrets_manager.ci_metadata_full_path(secret.name),
          "read"
        )
        secrets_manager_client.set_policy(policy)
      end
    end
  end
end
