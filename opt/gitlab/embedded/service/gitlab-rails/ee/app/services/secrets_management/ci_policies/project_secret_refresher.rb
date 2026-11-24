# frozen_string_literal: true

module SecretsManagement
  module CiPolicies
    class ProjectSecretRefresher < BaseSecretRefresher
      private

      delegate :ci_policy_name, to: :secrets_manager

      # Returns [from_policy, to_policy] representing the policies to transition:
      # - Delete: [current, nil] - remove from current policy
      # - Transition: [old, new] - move from old to new policy (when environment or branch changed)
      # - New/unchanged: [nil, current] - add to current policy
      def policies_to_transition(secret, delete_operation: false)
        if delete_operation
          # A create interrupted before writing metadata never added the secret to a policy
          return [nil, nil] if secret.environment.blank? || secret.branch.blank?

          [ci_policy_name(secret.environment, secret.branch), nil]
        elsif needs_policy_transition?(secret)
          [
            ci_policy_name(secret.environment_was, secret.branch_was),
            ci_policy_name(secret.environment, secret.branch)
          ]
        else
          [nil, ci_policy_name(secret.environment, secret.branch)]
        end
      end

      def needs_policy_transition?(secret)
        return false unless secret.environment_changed? || secret.branch_changed?

        secret.environment_was.present? || secret.branch_was.present?
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
          branch = metadata.dig('custom_metadata', 'branch')
          next unless environment && branch

          secret_policy_name = secrets_manager.ci_policy_name(environment, branch)
          count += 1 if secret_policy_name == policy_name
        end

        count
      end
    end
  end
end
