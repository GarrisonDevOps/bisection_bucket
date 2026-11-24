# frozen_string_literal: true

module Security
  module ScanResultPolicies
    class Rules
      def initialize(rules)
        @rules = (rules || []).map { |rule| Security::ScanResultPolicies::Rule.new(rule) }
      end

      attr_reader :rules
    end
  end
end
