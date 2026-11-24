# frozen_string_literal: true

module SecretsManagement
  module GroupSecrets
    class DeleteService < GroupBaseService
      include Secrets::DeleteServiceHelpers
      include GroupSecrets::SecretRefresherHelper

      def execute(name)
        execute_secret_deletion(resource: group, name: name)
      end

      private

      delegate :secrets_manager, to: :group

      def read_secret(name)
        GroupSecrets::ReadMetadataService.new(group, current_user)
          .execute(name, write_capability: BaseSecretsPermission::CAPABILITIES[:delete])
      end
    end
  end
end
