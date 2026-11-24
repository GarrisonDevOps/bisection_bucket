# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsManagerJwt < GlobalSecretsManagerJwt
    attr_reader :project

    def initialize(project:, current_user: nil, ttl: DEFAULT_TTL)
      super(current_user: current_user, ttl: ttl)
      @project = project
    end

    private

    def resource_claims
      # The user_ claims are optional. These claims are not checked during authentication.
      # The user_claims exist to provide audit traceability context about the user performing every action in Openbao

      ::JSONWebToken::UserProjectTokenClaims
        .new(project: project, user: current_user)
        .generate
    end
  end
end
