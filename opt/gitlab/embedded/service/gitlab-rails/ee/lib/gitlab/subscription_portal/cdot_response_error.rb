# frozen_string_literal: true

module Gitlab
  module SubscriptionPortal
    # Base class for the per-endpoint errors. It carries CDot's actual response
    # so the fail-closed log line can say what CDot answered.
    class CdotResponseError < StandardError
      # CDot did not decide anything about the customer on these, so they count
      # as an outage, like a dropped connection.
      UNAVAILABLE_STATUSES = [500, 502, 503, 504].freeze

      def self.unavailable_status?(code)
        UNAVAILABLE_STATUSES.include?(code)
      end

      def self.unavailable_transport?(error)
        unavailable_transport_errors.any? { |klass| error.is_a?(klass) }
      end

      # The subset of Gitlab::HTTP::HTTP_ERRORS that means CDot could not be reached. The rest
      # (SSRF, redirect, size and header guards, unreadable replies) is our side, so it fails closed.
      # A method, not a constant: Gitlab::HTTP needs the Rails-loaded gem, and the response classes
      # that inherit from here are covered by fast_spec_helper specs.
      def self.unavailable_transport_errors
        @unavailable_transport_errors ||= (::Gitlab::HTTP::HTTP_TIMEOUT_ERRORS + [
          EOFError, SocketError, OpenSSL::SSL::SSLError,
          Errno::ECONNRESET, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, Errno::ENETUNREACH,
          Errno::EADDRNOTAVAIL, Errno::EAFNOSUPPORT, Errno::ETIMEDOUT
        ]).freeze
      end

      attr_reader :cdot_status, :cdot_block_reason

      def initialize(message = nil, cdot_status: nil, cdot_block_reason: nil)
        @cdot_status = cdot_status
        @cdot_block_reason = cdot_block_reason

        super(message)
      end
    end
  end
end
