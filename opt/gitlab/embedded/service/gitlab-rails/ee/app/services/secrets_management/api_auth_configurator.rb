# frozen_string_literal: true

module SecretsManagement
  # Configures the non-CI API auth on an SM's OpenBao namespace: the `api_jwt`
  # mount, its JWT config, and the `all_api` CEL role. Idempotent, so it is
  # safe to run on an already-provisioned SM.
  #
  # Shared by the provision flow (new enrollments) and the api_jwt backfill
  # Rake task (existing enrollments) so the two never drift. The caller passes
  # a client already scoped to the SM's namespace: the provision flow uses the
  # per-resource management client, the backfill uses the global privileged
  # client scoped to the SM's namespace path.
  class ApiAuthConfigurator
    def initialize(client:, secrets_manager:, resource_id:)
      @client = client
      @secrets_manager = secrets_manager
      @resource_id = resource_id
    end

    def configure
      client.enable_auth_engine(
        secrets_manager.api_auth_mount,
        secrets_manager.api_auth_type,
        allow_existing: true
      )

      client.configure_jwt(
        secrets_manager.api_auth_mount,
        secrets_manager.class.jwt_issuer,
        Gitlab::CurrentSettings.ci_jwt_signing_key
      )

      client.update_jwt_cel_role(
        secrets_manager.api_auth_mount,
        secrets_manager.api_auth_role,
        cel_program: secrets_manager.api_auth_cel_program(resource_id),
        bound_audiences: [secrets_manager.class.jwt_audience]
      )
    end

    private

    attr_reader :client, :secrets_manager, :resource_id
  end
end
