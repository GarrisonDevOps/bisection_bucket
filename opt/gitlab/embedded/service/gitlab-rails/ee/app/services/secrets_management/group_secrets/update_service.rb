# frozen_string_literal: true

module SecretsManagement
  module GroupSecrets
    class UpdateService < GroupBaseService
      include Secrets::UpdateServiceHelpers
      include GroupSecrets::SecretRefresherHelper

      def execute(
        name:,
        metadata_cas:,
        value: nil,
        description: nil,
        environment: nil,
        protected: nil,
        rotation_interval_days: nil
      )
        with_exclusive_lease_for(group) do
          read_result = read_secret(name)
          break read_result unless read_result.success?

          group_secret = read_result.payload[:secret]
          group_secret.description = description unless description.nil?
          group_secret.environment = environment unless environment.nil?
          group_secret.protected = protected unless protected.nil?

          break error_response(group_secret) unless group_secret.valid_for_update?

          group_secret.rotation_info = build_secret_rotation_info(group_secret, metadata_cas, rotation_interval_days)

          # If the OpenBao write below fails, the rotation reminder cron cleans up this orphaned row.
          if !group_secret.rotation_info&.upsert && group_secret.rotation_info&.invalid?
            break secret_rotation_info_invalid_error(group_secret)
          end

          execute_secret_update(
            secret: group_secret,
            custom_metadata: {
              environment: group_secret.environment,
              protected: group_secret.protected.to_s,
              secret_rotation_info_id: group_secret.rotation_info&.id
            },
            value: value,
            metadata_cas: metadata_cas
          )
        end
      end

      private

      delegate :secrets_manager, to: :group

      def read_secret(name)
        # No need to include rotation info in this case because we just want to upsert if ever
        GroupSecrets::ReadMetadataService.new(group, current_user)
          .execute(name, include_rotation_info: false, write_capability: BaseSecretsPermission::CAPABILITIES[:update])
      end

      def build_secret_rotation_info(secret, metadata_cas, rotation_interval_days)
        return unless rotation_interval_days

        GroupSecretRotationInfo.new(
          group: group,
          secret_name: secret.name,
          rotation_interval_days: rotation_interval_days,
          secret_metadata_version: (metadata_cas || secret.metadata_version) + 1
        )
      end

      def refresh_policies_after_update(group_secret)
        refresh_secret_ci_policies(group_secret)
      end
    end
  end
end
