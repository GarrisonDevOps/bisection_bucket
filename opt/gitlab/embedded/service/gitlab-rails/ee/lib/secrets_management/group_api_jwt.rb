# frozen_string_literal: true

module SecretsManagement
  # JWT minted for non-CI API access to a group's secrets. See ProjectApiJwt for
  # the rationale: same user claims as GroupUserJwt, but with an `api` scope and
  # an `auth_via` claim recording the token type used.
  class GroupApiJwt < GroupUserJwt
    SCOPE = 'api'

    def initialize(group:, current_user:, auth_via:, ttl: DEFAULT_TTL)
      super(group: group, current_user: current_user, ttl: ttl)
      @auth_via = auth_via
    end

    def payload
      claims = super
      claims[:secrets_manager_scope] = SCOPE
      claims[:auth_via] = @auth_via
      claims
    end
  end
end
