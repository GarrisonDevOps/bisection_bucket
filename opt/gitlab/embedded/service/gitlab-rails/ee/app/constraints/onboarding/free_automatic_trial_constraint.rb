# frozen_string_literal: true

module Onboarding
  class FreeAutomaticTrialConstraint
    def matches?(request)
      user = request.env['warden']&.user

      return false unless user
      return false unless ::Onboarding::FreeRegistration.unification_enabled?
      return false unless ::Onboarding::UserStatus.new(user).free_registration?

      # Genuine trial users are matched earlier by TrialUserConstraint, so this only
      # catches the first free submit that opts into "My team".
      ::Gitlab::Utils.to_boolean(
        request.params[:onboarding_status_setup_for_company], default: false
      )
    end
  end
end
