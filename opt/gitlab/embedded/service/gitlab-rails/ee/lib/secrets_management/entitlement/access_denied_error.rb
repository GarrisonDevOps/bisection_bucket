# frozen_string_literal: true

module SecretsManagement
  class Entitlement
    # Raised (not just returned false) so the caller can drop the build with the right reason.
    AccessDeniedError = Class.new(StandardError)
  end
end
