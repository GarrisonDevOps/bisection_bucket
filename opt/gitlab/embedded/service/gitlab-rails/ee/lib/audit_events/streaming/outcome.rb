# frozen_string_literal: true

module AuditEvents
  module Streaming
    # Result of one delivery call to an external destination. A failed call
    # carries the error and its category; a delivered call carries the response.
    class Outcome
      # Half the 8s HTTP timeout, so a destination drifting towards it is logged before it fails.
      SLOW_DELIVERY_SECONDS = 4

      attr_reader :error, :error_category, :response
      attr_accessor :duration_s

      def initialize(error: nil, error_category: nil, response: nil, duration_s: nil)
        @error = error
        @error_category = error_category
        @response = response
        @duration_s = duration_s
      end

      def delivered?
        error.nil?
      end

      def internal_error?
        error_category == :internal_error
      end

      def status_code
        return response.code if response.respond_to?(:code)

        error.status if error.respond_to?(:status)
      end

      # A non-2xx only arrives as a delivered response while
      # audit_event_streaming_fail_on_non_2xx_response is off; with it on
      # the destination raises and the failure path logs it instead.
      def rejected?
        response.respond_to?(:code) && !(200..299).cover?(response.code)
      end

      def slow_or_rejected?
        duration_s.to_f >= SLOW_DELIVERY_SECONDS || rejected?
      end

      def logged_duration_s
        duration_s.to_f.round(Gitlab::InstrumentationHelper::DURATION_PRECISION)
      end
    end
  end
end
