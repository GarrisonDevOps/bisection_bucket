# frozen_string_literal: true

module Onboarding
  class TrialUserConstraint
    include Gitlab::Experiment::Dsl

    def matches?(request)
      user = request.env['warden']&.user

      return false unless user

      ::Onboarding::UserStatus.new(user).trial_registration?
    end
  end
end
