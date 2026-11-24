# frozen_string_literal: true

module SecretsManagement
  module ProjectSecrets
    module SecretRefresherHelper
      def refresh_secret_ci_policies(project_secret, delete_operation: false)
        refresher = CiPolicies::ProjectSecretRefresher.new(
          secrets_manager,
          project_secrets_manager_client
        )
        refresher.refresh_ci_policies_for(project_secret, delete_operation: delete_operation)
      end
    end
  end
end
