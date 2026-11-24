# frozen_string_literal: true

module SecretsManagement
  class GlobalSecretsManagerJwt < Gitlab::Ci::JwtBase
    DEFAULT_TTL = 30.seconds
    SYSTEM_UID = 'gitlab_secrets_manager'

    attr_reader :current_user, :ttl

    def initialize(current_user: nil, ttl: DEFAULT_TTL, aud: nil)
      super()
      @current_user = current_user
      @ttl = ttl
      @aud = aud
    end

    def payload
      now = Time.now.to_i

      base_payload = {
        iss: Gitlab.config.gitlab.url,
        iat: now,
        nbf: now,
        exp: now + ttl.to_i,
        jti: SecureRandom.uuid,
        aud: aud,
        sub: SYSTEM_UID,
        secrets_manager_scope: 'privileged',
        correlation_id: Labkit::Correlation::CorrelationId.current_id
      }

      base_payload.merge(resource_claims)
    end

    private

    def aud
      @aud || SecretsManagement::BaseSecretsManager.jwt_audience
    end

    # We have some application level actions like recovery key generation for the whole app
    # These actions are NOT performed in the context of a specific user or a project
    # We use SYSTEM_UID in these cases
    # Only user_id is required by Openbao for authentication via the user_claim mapping
    def resource_claims
      {
        user_id: SYSTEM_UID
      }
    end
  end
end
