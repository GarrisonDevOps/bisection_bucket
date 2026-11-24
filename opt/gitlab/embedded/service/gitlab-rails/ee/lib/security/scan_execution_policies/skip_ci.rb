# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class SkipCi
      def initialize(skip_ci)
        @skip_ci = skip_ci || {}
      end

      def allowed
        skip_ci[:allowed]
      end

      def allowlist
        skip_ci[:allowlist] || {}
      end

      def allowlist_users
        allowlist[:users] || []
      end

      private

      attr_reader :skip_ci
    end
  end
end
