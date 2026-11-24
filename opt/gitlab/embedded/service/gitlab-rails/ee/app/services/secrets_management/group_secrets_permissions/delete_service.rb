# frozen_string_literal: true

module SecretsManagement
  module GroupSecretsPermissions
    class DeleteService < GroupBaseService
      include SecretsPermissions::DeleteServiceHelpers

      private

      def resource
        group
      end

      def client
        group_secrets_manager_client
      end
    end
  end
end
