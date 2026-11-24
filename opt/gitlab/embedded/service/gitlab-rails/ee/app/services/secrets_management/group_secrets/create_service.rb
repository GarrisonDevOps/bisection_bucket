# frozen_string_literal: true

module SecretsManagement
  module GroupSecrets
    class CreateService < GroupBaseService
      include Secrets::CreateServiceHelpers
      include GroupSecrets::SecretRefresherHelper

      def execute(name:, value:, environment:, protected:, description: nil, rotation_interval_days: nil)
        with_exclusive_lease_for(group) do
          group_secret = GroupSecret.new(
            name: name,
            description: description,
            group: group,
            environment: environment,
            protected: protected
          )

          secret_rotation_info = build_secret_rotation_info(name, rotation_interval_days) if rotation_interval_days
          group_secret.rotation_info = secret_rotation_info

          execute_secret_creation(
            secret: group_secret,
            custom_metadata: {
              environment: environment,
              protected: protected.to_s
            },
            value: value
          )
        end
      end

      private

      delegate :secrets_manager, to: :group

      def secrets_count_service
        SecretsManagement::GroupSecretsCountService.new(group, current_user)
      end

      def build_secret_rotation_info(name, rotation_interval_days)
        GroupSecretRotationInfo.new(
          group: group,
          secret_name: name,
          rotation_interval_days: rotation_interval_days,
          secret_metadata_version: 1
        )
      end

      def read_secret(group_secret)
        GroupSecrets::ReadMetadataService.new(group, current_user)
          .execute(group_secret.name, write_capability: BaseSecretsPermission::CAPABILITIES[:create])
      end
    end
  end
end
