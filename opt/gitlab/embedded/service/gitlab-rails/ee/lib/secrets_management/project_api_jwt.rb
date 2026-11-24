# frozen_string_literal: true

module SecretsManagement
  # JWT minted for non-CI API access to a project's secrets. It carries the same
  # user claims as ProjectUserJwt so the OpenBao CEL role can resolve the same
  # per-principal policies, but with an `api` scope and an `auth_via` claim that
  # records which token type was used, for audit traceability.
  class ProjectApiJwt < ProjectUserJwt
    SCOPE = 'api'

    def initialize(project:, current_user:, auth_via:, ttl: DEFAULT_TTL)
      super(project: project, current_user: current_user, ttl: ttl)
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
