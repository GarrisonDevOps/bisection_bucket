# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    # Result of POST /api/v1/billing/usage/trials for Secrets Manager.
    # CDot is the source of truth for eligibility, so this PORO only carries
    # the outcome: success, or a failure with a normalized `error_code` derived
    # from CDot's HTTP status. `Error` is raised for protocol/deployment
    # failures the mutation cannot translate into a user-facing message.
    class SecretsManagerStartTrialResponse < Data.define(
      :success,
      :error_code,
      :error_message
    )
      Error = Class.new(StandardError)

      ERROR_CODES = %i[trial_already_active ineligible not_found].freeze

      def initialize(success:, error_code: nil, error_message: nil)
        validate_error_code!(success, error_code)
        super
      end

      def success?
        success
      end

      private

      def validate_error_code!(success, error_code)
        return if success && error_code.nil?
        return if !success && ERROR_CODES.include?(error_code)

        raise ArgumentError,
          "Invalid start-trial result: success=#{success.inspect}, error_code=#{error_code.inspect} " \
            "(failures expect one of #{ERROR_CODES.inspect})"
      end
    end
  end
end
