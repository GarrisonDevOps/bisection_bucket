# frozen_string_literal: true

module Onboarding
  class SubscriptionUserConstraint
    def matches?(request)
      user = request.env['warden']&.user

      return false unless user

      ::Onboarding::UserStatus.new(user).subscription_registration?
    end
  end
end
