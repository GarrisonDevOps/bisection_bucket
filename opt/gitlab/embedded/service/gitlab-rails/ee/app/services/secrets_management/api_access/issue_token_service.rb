# frozen_string_literal: true

module SecretsManagement
  module ApiAccess
    # Mints a short-lived JWT for non-CI API access to a project or group's
    # secrets and assembles the OpenBao connection details the client needs.
    # The caller is responsible for authorization; this service only issues the
    # token for an already-authorized user.
    class IssueTokenService
      TTL = 5.minutes

      Token = Struct.new(
        :token, :expires_at, :server_url, :namespace, :kv_mount, :secrets_path, :auth_mount, :auth_role,
        keyword_init: true
      )

      def initialize(secrets_manager, current_user, auth_via:)
        @secrets_manager = secrets_manager
        @current_user = current_user
        @auth_via = auth_via
      end

      def execute
        return inactive_response unless secrets_manager.active_after_refresh?

        ServiceResponse.success(payload: { token: build_token })
      end

      private

      attr_reader :secrets_manager, :current_user, :auth_via

      def build_token
        Token.new(
          token: jwt.encoded,
          expires_at: TTL.from_now.utc.iso8601,
          server_url: secrets_manager.class.server_url,
          namespace: namespace_path,
          kv_mount: secrets_manager.ci_secrets_mount_path,
          secrets_path: secrets_manager.ci_data_root_path,
          # `all_api` is a CEL role, which authenticates at `auth/<mount>/cel/login`.
          # Stock Vault clients (and ESO) build the login as `auth/<path>/login`, so
          # we hand back the `/cel` subpath here rather than the bare mount.
          auth_mount: "#{secrets_manager.api_auth_mount}/cel",
          auth_role: secrets_manager.api_auth_role
        )
      end

      def project_scoped?
        secrets_manager.is_a?(SecretsManagement::ProjectSecretsManager)
      end

      def jwt
        if project_scoped?
          SecretsManagement::ProjectApiJwt.new(
            project: secrets_manager.project, current_user: current_user, auth_via: auth_via, ttl: TTL
          )
        else
          SecretsManagement::GroupApiJwt.new(
            group: secrets_manager.group, current_user: current_user, auth_via: auth_via, ttl: TTL
          )
        end
      end

      def namespace_path
        if project_scoped?
          secrets_manager.full_project_namespace_path
        else
          secrets_manager.full_group_namespace_path
        end
      end

      def inactive_response
        ServiceResponse.error(message: 'Secrets manager is not active')
      end
    end
  end
end
