# frozen_string_literal: true

module SecretsManagement
  module SecretsManagers
    module PipelineHelper
      extend ActiveSupport::Concern

      SECRETS_MOUNT_PATH = "secrets/kv"
      DATA_ROOT  = "explicit"
      AUTH_MOUNT = "pipeline_jwt"
      AUTH_ROLE  = "all_pipelines"
      AUTH_TYPE  = "jwt"

      def ci_secrets_mount_path
        SECRETS_MOUNT_PATH
      end

      def ci_data_root_path
        DATA_ROOT
      end

      def ci_data_path(secret_key = nil)
        [ci_data_root_path, secret_key].compact.join('/')
      end

      def sanitized_ci_data_path(secret_key)
        unless secret_key.match?(::SecretsManagement::BaseSecret::SECRET_NAME_FORMAT)
          raise ArgumentError, "Invalid secret key: #{secret_key.inspect}"
        end

        ci_data_path(secret_key)
      end

      def ci_full_path(secret_key)
        [ci_secrets_mount_path, 'data', ci_data_path(secret_key)].compact.join('/')
      end

      def ci_metadata_full_path(secret_key)
        [ci_secrets_mount_path, 'metadata', ci_data_path(secret_key)].compact.join('/')
      end

      def detailed_metadata_path(secret_key)
        [ci_secrets_mount_path, 'detailed-metadata', ci_data_path(secret_key)].compact.join('/')
      end

      def ci_auth_mount
        AUTH_MOUNT
      end

      def ci_auth_role
        AUTH_ROLE
      end

      def ci_auth_type
        AUTH_TYPE
      end

      def ci_jwt(build)
        track_ci_jwt_generation(build)
        SecretsManagement::PipelineJwt.for_build(build, aud: aud)
      end

      private

      def track_ci_jwt_generation(build)
        track_internal_event(
          'generate_id_token_for_secrets_manager_authentication',
          project: build.project,
          namespace: build.project.namespace,
          user: build.user
        )
      end
    end
  end
end
