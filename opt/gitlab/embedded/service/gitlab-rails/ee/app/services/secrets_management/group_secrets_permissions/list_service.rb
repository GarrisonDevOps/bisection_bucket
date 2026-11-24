# frozen_string_literal: true

module SecretsManagement
  module GroupSecretsPermissions
    class ListService < GroupBaseService
      include SecretsPermissions::ListServiceHelpers

      private

      def resource
        group
      end

      def client
        group_secrets_manager_client
      end

      def permission_class
        SecretsManagement::GroupSecretsPermission
      end
    end
  end
end
