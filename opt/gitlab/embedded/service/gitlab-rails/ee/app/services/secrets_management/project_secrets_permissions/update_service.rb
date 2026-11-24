# frozen_string_literal: true

module SecretsManagement
  module ProjectSecretsPermissions
    class UpdateService < ProjectBaseService
      include SecretsPermissions::UpdateServiceHelpers

      private

      def resource
        project
      end

      def client
        project_secrets_manager_client
      end

      def permission_class
        SecretsManagement::ProjectSecretsPermission
      end
    end
  end
end
