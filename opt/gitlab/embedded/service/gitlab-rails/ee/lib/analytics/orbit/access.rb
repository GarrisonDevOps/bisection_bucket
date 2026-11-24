# frozen_string_literal: true

module Analytics
  module Orbit
    class Access < Data.define(:state, :reason, :turn_on_denial_reason, :trial)
      STATES = %i[
        not_configured
        unlicensed
        trial_eligible
        trial_active
        trial_ended
        trial_not_eligible
        trial_status_unavailable
        licensed
      ].freeze

      REASONS = %i[
        free_plan
        no_license
        no_access
        trial_expired
        credits_exhausted
        plan
        promo_add_on
        beta
      ].freeze

      TURN_ON_DENIAL_REASONS = %i[forbidden trial_required purchase_required trial_ended unavailable].freeze
    end
  end
end
