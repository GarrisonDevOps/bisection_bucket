# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    class SecretsManagerConsumerResolveResponse < Data.define(
      :blocked,
      :blocked_reason,
      :cache_ttl
    )
      Error = Class.new(SecretsManagerResponseError)
      UnavailableError = SecretsManagerResponseError::UnavailableError

      # Reasons the entitlement resolver knows how to map. CDot's vocabulary is
      # wider and can grow: unknown reasons are carried as-is, never raised on.
      BLOCKED_REASONS = %i[
        credits_exhausted
        on_demand_disabled
        subscription_grace_period_expired
        no_billable_source_error
        usage_not_allowed
      ].freeze

      def initialize(blocked:, blocked_reason: nil, cache_ttl: nil)
        validate_blocked_reason!(blocked, blocked_reason)
        super
      end

      private

      # Only the shape is validated: a reason on a non-blocked response is a
      # contract violation, but an unrecognized reason value is not.
      def validate_blocked_reason!(blocked, reason)
        return if reason.nil?
        return if blocked

        raise ArgumentError,
          "CDot consumer-resolve blocked_reason #{reason.inspect} requires blocked: true"
      end
    end
  end
end
