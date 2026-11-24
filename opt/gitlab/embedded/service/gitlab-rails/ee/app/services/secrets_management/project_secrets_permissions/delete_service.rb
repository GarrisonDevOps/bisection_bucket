# frozen_string_literal: true

module SecretsManagement
  module ProjectSecretsPermissions
    class DeleteService < ProjectBaseService
      include SecretsPermissions::DeleteServiceHelpers

      private

      def resource
        project
      end

      def client
        project_secrets_manager_client
      end
    end
  end
end
