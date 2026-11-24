# frozen_string_literal: true

module SecretsManagement
  module Secrets
    module ReadMetadataServiceHelpers
      include SecretsManagement::ErrorMapping

      private

      # Reads a secret's metadata as the user. Create, update and delete read the
      # secret first, but a grant can hold those actions without read_metadata.
      # For them, when OpenBao denies the read and the user holds
      # `write_capability` on this secret, the read runs as the application;
      # the write itself still runs as the user.
      #
      # @param name [String] the secret name
      # @param write_capability [String, nil] the OpenBao capability the caller is about to use
      # @return [Hash, nil] the secret metadata, or nil when the secret does not exist
      def read_secret_metadata_for(name, write_capability)
        user_client.read_secret_metadata(secrets_manager.ci_secrets_mount_path, secrets_manager.ci_data_path(name))
      rescue SecretsManagerClient::ApiError => e
        raise unless write_capability && permission_error?(e.message) && user_capable?(name, write_capability)

        base_secrets_manager_client
          .with_namespace(secrets_manager.full_namespace_path)
          .read_secret_metadata(secrets_manager.ci_secrets_mount_path, secrets_manager.ci_data_path(name))
      end

      def user_capable?(name, capability)
        path = secrets_manager.ci_full_path(name)
        response = user_client.capabilities_self(paths: [path])

        Array(response&.dig('data', path)).include?(capability)
      rescue SecretsManagerClient::ApiError
        false
      end
    end
  end
end
