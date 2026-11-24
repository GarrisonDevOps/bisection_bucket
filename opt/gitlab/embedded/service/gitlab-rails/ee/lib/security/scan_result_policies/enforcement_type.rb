# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class EnforcementType
      DEFAULT_ENFORCEMENT_TYPE = 'enforce'

      def initialize(enforcement_type)
        @enforcement_type = enforcement_type || DEFAULT_ENFORCEMENT_TYPE
      end

      def warn?
        enforcement_type == 'warn'
      end

      def enforce?
        enforcement_type == 'enforce'
      end

      private

      attr_reader :enforcement_type
    end
  end
end
