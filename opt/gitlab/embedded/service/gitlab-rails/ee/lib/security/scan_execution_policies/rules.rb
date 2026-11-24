# frozen_string_literal: true

module Security
  module ScanExecutionPolicies
    class Rules
      include Enumerable

      def initialize(rules)
        @rules = (rules || []).map { |rule| Security::ScanExecutionPolicies::Rule.new(rule) }
      end

      attr_reader :rules

      delegate :each, :[], :map, to: :rules
    end
  end
end
