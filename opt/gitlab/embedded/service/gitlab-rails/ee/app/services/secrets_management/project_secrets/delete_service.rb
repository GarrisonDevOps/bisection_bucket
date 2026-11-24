# frozen_string_literal: true

module SecretsManagement
  module ProjectSecrets
    class DeleteService < ProjectBaseService
      include Secrets::DeleteServiceHelpers
      include ProjectSecrets::SecretRefresherHelper

      def execute(name)
        execute_secret_deletion(resource: project, name: name)
      end

      private

      delegate :secrets_manager, to: :project

      def read_secret(name)
        ProjectSecrets::ReadMetadataService.new(project, current_user)
          .execute(name, write_capability: BaseSecretsPermission::CAPABILITIES[:delete])
      end
    end
  end
end
