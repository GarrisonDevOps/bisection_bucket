# frozen_string_literal: true

module SecretsManagement
  module Secrets
    module UpdateServiceHelpers
      def execute_secret_update(secret:, custom_metadata:, value:, metadata_cas:)
        return secrets_manager_inactive_response unless secrets_manager&.active_after_refresh?

        update_secret(secret, value, custom_metadata, metadata_cas)
      end

      def update_secret(secret, value, custom_metadata, metadata_cas)
        return error_response(secret) unless secret.valid_for_update?

        update_started_at = Time.current.utc.iso8601
        secret.update_started_at = update_started_at

        metadata = build_update_custom_metadata(
          secret,
          custom_metadata,
          update_started_at: update_started_at,
          update_completed_at: nil
        )

        # NOTE: The current implementation makes two separate API calls (one for the value, one for metadata).
        # In the future, the secret value update will be handled directly in the frontend for better security,
        # before calling this service. However, the metadata update and policy management will still be handled
        # in this Rails backend service, as they contain essential information for access control.

        # We need to do the metadata update first just in case the metadata_cas does not match
        user_client.update_kv_secret_metadata(
          secrets_manager.ci_secrets_mount_path,
          secrets_manager.ci_data_path(secret.name),
          metadata,
          metadata_cas: metadata_cas
        )

        if value
          user_client.update_kv_secret(
            secrets_manager.ci_secrets_mount_path,
            secrets_manager.ci_data_path(secret.name),
            value
          )
        end

        # Must run after the user client writes so a denied update leaves CI policies untouched
        refresh_policies_after_update(secret) if respond_to?(:refresh_policies_after_update, true)

        secret.metadata_version = metadata_cas ? metadata_cas + 1 : nil

        complete_secret_update(secret, custom_metadata, update_started_at, metadata_cas)

        ServiceResponse.success(payload: { secret: secret })
      rescue SecretsManagerClient::ApiError => e
        raise e unless e.message.include?('metadata check-and-set parameter does not match the current version')

        secret.errors.add(
          :base,
          "This secret has been modified recently. Please refresh the page and try again."
        )
        error_response(secret)
      end

      def complete_secret_update(secret, custom_metadata, update_started_at, metadata_cas)
        update_completed_at = Time.current.utc.iso8601
        secret.update_completed_at = update_completed_at

        metadata = build_update_custom_metadata(
          secret,
          custom_metadata,
          update_started_at: update_started_at,
          update_completed_at: update_completed_at
        )

        user_client.update_kv_secret_metadata(
          secrets_manager.ci_secrets_mount_path,
          secrets_manager.ci_data_path(secret.name),
          metadata,
          metadata_cas: (metadata_cas ? metadata_cas + 1 : nil)
        )
      end

      def secret_rotation_info_invalid_error(secret)
        secret.rotation_info.errors.full_messages.each do |message|
          secret.errors.add(:base, "Rotation configuration error: #{message}")
        end

        error_response(secret)
      end

      def build_update_custom_metadata(secret, custom_metadata, update_started_at:, update_completed_at: nil)
        {
          description: secret.description,
          update_started_at: update_started_at,
          update_completed_at: update_completed_at,
          create_completed_at: secret.create_completed_at
        }.merge(custom_metadata).compact
      end

      def error_response(secret)
        ServiceResponse.error(
          message: secret.errors.full_messages.to_sentence,
          payload: { secret: secret }
        )
      end
    end
  end
end
