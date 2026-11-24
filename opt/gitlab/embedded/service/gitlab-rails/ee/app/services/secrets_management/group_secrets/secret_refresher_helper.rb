# frozen_string_literal: true

module SecretsManagement
  module GroupSecrets
    module SecretRefresherHelper
      def refresh_secret_ci_policies(group_secret, delete_operation: false)
        refresher = CiPolicies::GroupSecretRefresher.new(
          secrets_manager,
          group_secrets_manager_client
        )
        refresher.refresh_ci_policies_for(group_secret, delete_operation: delete_operation)
      end
    end
  end
end
