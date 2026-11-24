# frozen_string_literal: true

module Onboarding
  class InviteUserConstraint
    def matches?(request)
      user = request.env['warden']&.user

      return false unless user

      ::Onboarding::UserStatus.new(user).invite_registration?
    end
  end
end
