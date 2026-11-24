# frozen_string_literal: true

module SecretsManagement
  module Secrets
    module CreateServiceHelpers
      MAX_SECRET_SIZE = 10000

      def secrets_limit_exceeded?
        return false if secrets_manager.nil?

        secrets_count_service.secrets_limit_exceeded?
      end

      def secrets_limit
        secrets_manager.secrets_limit
      end

      def secrets_limit_exceeded_response
        ServiceResponse.error(
          message: format(
            _("Maximum number of secrets (%{limit}) for this %{scope} has been reached. " \
              "Please delete unused secrets or contact your administrator to increase the limit."),
            limit: secrets_limit,
            scope: secrets_manager.scope_name
          ),
          reason: :secrets_limit_exceeded
        )
      end

      def execute_secret_creation(secret:, custom_metadata:, value:)
        return secrets_manager_inactive_response unless secrets_manager&.active_after_refresh?
        return secrets_limit_exceeded_response if secrets_limit_exceeded?

        result = store_secret(secret, value, custom_metadata)

        enqueue_namespace_secret_count_refresh if result.success?

        result
      end

      def store_secret(secret, value, custom_metadata)
        return error_response(secret) unless secret.valid?
        return secret_exists_error(secret) if secret_exists?(secret)

        # Before removing MAX_SECRET_SIZE from the above and sending value directly
        # to OpenBao, ensure it has been updated with request parameter
        # size limiting quotas.
        if value.bytesize > MAX_SECRET_SIZE
          secret.errors.add(:base, "Length of secret value exceeds allowed limits (10k bytes).")
          return error_response(secret)
        end

        # Based on https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/secret_manager/decisions/010_secret_rotation_metadata_storage/
        # we want to create the secret rotation info record first.
        if !secret.rotation_info&.upsert && secret.rotation_info&.invalid?
          return secret_rotation_info_invalid_error(secret)
        end

        # The follow API calls are ordered such that they fail closed: first we
        # create the secret and its metadata and then attach policy to it. If we
        # fail to attach policy, no pipelines can access it and only permitted
        # users can modify it in the future. Updating a secret to set missing
        # scoping attributes (e.g. environment) will then allow pipelines to access the secret.

        start_secret_creation!(secret, value, custom_metadata)

        refresh_secret_ci_policies(secret)

        complete_secret_creation!(secret, custom_metadata)

        # After complete_secret_creation! updates the metadata with metadata_cas: 1,
        # OpenBao increments the version to 2. We're setting secret.metadata_version = 2 in-memory to reflect the
        # current state in OpenBao, so the GraphQL response returns the correct version to the client.
        # This is needed for the next update operation - the client will use metadataCas: 2 for optimistic locking.
        secret.metadata_version = 2

        ServiceResponse.success(payload: { secret: secret })
      end

      def secret_exists?(secret)
        result = read_secret(secret)
        result.success?
      end

      def secret_exists_error(secret)
        secret.errors.add(:base, 'Secret already exists.')
        error_response(secret)
      end

      def kv_mount_path
        secrets_manager.ci_secrets_mount_path
      end

      def kv_data_path(secret_name)
        secrets_manager.ci_data_path(secret_name)
      end

      def write_secret_value!(secret, value, cas:)
        user_client.update_kv_secret(kv_mount_path, kv_data_path(secret.name), value, cas: cas)
      end

      def update_metadata_for(secret, custom_metadata, metadata_cas:)
        metadata = build_custom_metadata(
          secret,
          custom_metadata,
          create_completed_at: secret.create_completed_at
        )

        # Runs as the application, not the user. A secret's data and metadata paths
        # come into existence together, so whichever is written second is an update
        # as far as OpenBao is concerned - meaning a `create` grant could never
        # complete a creation. Keeping metadata on the app client leaves the value
        # write as the user-authorized step and lets `create` withhold update.
        base_secrets_manager_client
          .with_namespace(secrets_manager.full_namespace_path)
          .update_kv_secret_metadata(
            kv_mount_path,
            kv_data_path(secret.name),
            metadata,
            metadata_cas: metadata_cas
          )
      end

      # NOTE: The current implementation makes two separate API calls (one for the value, one for metadata).
      # In the future, the secret value creation will be handled directly in the frontend for better security,
      # before calling this service. However, the metadata update and policy management will still be handled
      # in this Rails backend service, as they contain essential information for access control.

      def start_secret_creation!(secret, value, custom_metadata)
        write_secret_value!(secret, value, cas: 0)
        update_metadata_for(secret, custom_metadata, metadata_cas: 0)
      end

      def complete_secret_creation!(secret, custom_metadata)
        secret.create_completed_at = Time.current.utc.iso8601
        update_metadata_for(secret, custom_metadata, metadata_cas: 1)
      end

      def secret_rotation_info_invalid_error(secret)
        secret.rotation_info.errors.full_messages.each do |message|
          secret.errors.add(:base, "Rotation configuration error: #{message}")
        end

        error_response(secret)
      end

      def build_custom_metadata(secret, custom_metadata, create_completed_at: nil)
        {
          description: secret.description,
          secret_rotation_info_id: secret.rotation_info&.id,
          create_completed_at: create_completed_at
        }.merge(custom_metadata).compact
      end

      def error_response(secret)
        ServiceResponse.error(
          message: secret.errors.full_messages.to_sentence,
          payload: { secret: secret }
        )
      end

      private

      def secrets_count_service
        raise NotImplementedError, "#{self.class} must implement #secrets_count_service"
      end

      def enqueue_namespace_secret_count_refresh
        namespace_id = secrets_manager&.namespace_id_for_secret_count
        return unless namespace_id

        ReconcileNamespaceSecretCountWorker.perform_async(namespace_id, current_user&.id)
      end
    end
  end
end
