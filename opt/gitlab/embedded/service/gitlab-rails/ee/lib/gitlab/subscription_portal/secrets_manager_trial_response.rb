# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    class SecretsManagerTrialResponse < Data.define(
      :state,
      :trial_started_at,
      :trial_expires_at,
      :credits_remaining,
      :credits_total,
      :on_demand_enabled,
      :cache_ttl
    )
      Error = Class.new(SecretsManagerResponseError)
      UnavailableError = SecretsManagerResponseError::UnavailableError

      STATES = %i[trial_eligible trial expired ineligible].freeze

      def initialize(
        state:,
        trial_started_at: nil,
        trial_expires_at: nil,
        credits_remaining: nil,
        credits_total: nil,
        on_demand_enabled: nil,
        cache_ttl: nil
      )
        validate_state!(state)
        super
      end

      private

      def validate_state!(state)
        return if STATES.include?(state)

        raise ArgumentError,
          "Unknown CDot state: #{state.inspect} (expected one of #{STATES.inspect})"
      end
    end
  end
end
