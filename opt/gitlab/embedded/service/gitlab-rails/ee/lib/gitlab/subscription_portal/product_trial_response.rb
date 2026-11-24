# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    class ProductTrialResponse < Data.define(
      :state,
      :trial_started_at,
      :trial_expires_at,
      :credits_remaining,
      :credits_total,
      :on_demand_enabled,
      :offer_duration_days,
      :offer_credits,
      :cache_ttl
    )
      Error = Class.new(CdotResponseError)
      # A subclass of Error, so one rescue also covers a CDot outage.
      UnavailableError = Class.new(Error)

      STATES = %i[trial_eligible trial expired ineligible].freeze

      def initialize( # rubocop:disable Metrics/ParameterLists -- one optional keyword per Data member
        state:,
        trial_started_at: nil,
        trial_expires_at: nil,
        credits_remaining: nil,
        credits_total: nil,
        on_demand_enabled: nil,
        offer_duration_days: nil,
        offer_credits: nil,
        cache_ttl: nil
      )
        validate_state!(state)
        super
      end

      def trial_active?
        state == :trial && !credits_exhausted?
      end

      def trial_ended?
        state == :expired || (state == :trial && credits_exhausted?)
      end

      private

      def credits_exhausted?
        !credits_remaining.nil? && credits_remaining <= 0
      end

      def validate_state!(state)
        return if STATES.include?(state)

        raise ArgumentError,
          "Unknown CDot state: #{state.inspect} (expected one of #{STATES.inspect})"
      end
    end
  end
end
