# frozen_string_literal: true

module Onboarding
  class StatusConvertToInviteService
    def initialize(user, initial_registration: false)
      @user = user
      @initial_registration = initial_registration
    end

    def execute
      return unless Onboarding.user_onboarding_in_progress?(user)

      if user.update(attributes)
        ServiceResponse.success(payload: payload)
      else
        ServiceResponse.error(message: user.errors.full_messages, payload: payload)
      end
    end

    private

    attr_reader :user, :registration_type, :initial_registration

    def payload
      { user: user }
    end

    def attributes
      attrs = { onboarding_status_registration_type: ::Onboarding::REGISTRATION_TYPE[:invite] }

      if initial_registration
        attrs[:onboarding_status_initial_registration_type] = ::Onboarding::REGISTRATION_TYPE[:invite]
      end

      attrs
    end
  end
end
