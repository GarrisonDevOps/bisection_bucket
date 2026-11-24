# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class FallbackBehavior
      def initialize(fallback_behavior)
        @fallback_behavior = fallback_behavior || {}
      end

      def fail_open?
        fallback_behavior[:fail] == 'open'
      end

      def fail_closed?
        fallback_behavior[:fail] == 'closed'
      end

      private

      attr_reader :fallback_behavior
    end
  end
end
