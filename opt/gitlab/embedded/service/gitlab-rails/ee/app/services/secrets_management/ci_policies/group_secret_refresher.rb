# frozen_string_literal: true

module SecretsManagement
  module CiPolicies
    class GroupSecretRefresher < BaseSecretRefresher
      private

      # Returns [from_policy, to_policy] representing the policies to transition:
      # - Delete: [current, nil] - remove from current policy
      # - Transition: [old, new] - move from old to new policy
      # - New/unchanged: [nil, current] - add to current policy
      def policies_to_transition(secret, delete_operation: false)
        if delete_operation
          # A create interrupted before writing metadata never added the secret to a policy
          return [nil, nil] if secret.environment.blank?

          [policy_name_for(secret), nil]
        elsif needs_policy_transition?(secret)
          [policy_name_for_previous(secret), policy_name_for(secret)]
        else
          [nil, policy_name_for(secret)]
        end
      end

      def needs_policy_transition?(secret)
        return false unless secret.environment_changed? || secret.protected_changed?

        secret.environment_was.present? || !secret.protected_was.nil?
      end

      def policy_name_for(secret)
        secrets_manager.ci_policy_name_for_environment(
          secret.environment,
          protected: secret.protected
        )
      end

      def policy_name_for_previous(secret)
        secrets_manager.ci_policy_name_for_environment(
          secret.environment_was,
          protected: secret.protected_was
        )
      end

      def should_delete_policy?(policy_name, secret:)
        count_secrets_for_policy(policy_name, exclude_secret_name: secret.name) == 0
      end

      def count_secrets_for_policy(policy_name, exclude_secret_name: nil)
        count = 0

        secrets_manager_client.list_secrets(
          secrets_manager.ci_secrets_mount_path,
          secrets_manager.ci_data_root_path
        ) do |secret|
          secret_name = secret['key']
          next if exclude_secret_name && secret_name == exclude_secret_name

          metadata = secret['metadata']
          next unless metadata

          environment = metadata.dig('custom_metadata', 'environment')
          protected = metadata.dig('custom_metadata', 'protected')
          next unless environment && !protected.nil?

          # Convert string to boolean if needed
          protected = protected.to_s == 'true'

          secret_policy_name = secrets_manager.ci_policy_name_for_environment(
            environment,
            protected: protected
          )
          count += 1 if secret_policy_name == policy_name
        end

        count
      end
    end
  end
end
