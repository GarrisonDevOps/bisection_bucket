# frozen_string_literal: true

module EE
  module AuthenticatesWithTwoFactor
    extend ::Gitlab::Utils::Override

    override :log_failed_two_factor
    def log_failed_two_factor(user, method)
      ::Authn::UnauthenticatedSecurityEventAuditor.new(user, method).execute
    end
  end
end
