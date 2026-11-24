# frozen_string_literal: true

module SecretsManagement
  # Shared by the project and group Initialize mutations. StartTrial and EnableAddOn
  # also provision, but they change billing state first, so they are not limited.
  module EnforcesInitializeRateLimit
    RATE_LIMIT_KEY = :secrets_manager_initialize

    private

    def initialize_rate_limited?(resource)
      # An existing secrets manager adds no OpenBao namespace, and the frontend
      # chain calls Initialize again after StartTrial has already provisioned.
      return false if resource.secrets_manager.present?

      root_namespace = resource.root_ancestor
      # The service rejects projects in user namespaces, so they are not counted.
      return false if root_namespace.user_namespace?

      ::Gitlab::ApplicationRateLimiter.throttled?(RATE_LIMIT_KEY, scope: { namespace: root_namespace })
    end

    # A payload error, not a raised one, so the frontend shows the message as-is.
    def initialize_rate_limited_response(payload_key)
      { payload_key => nil, errors: [::Gitlab::ApplicationRateLimiter.throttled_error_message] }
    end
  end
end
