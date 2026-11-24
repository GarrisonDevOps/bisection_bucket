# frozen_string_literal: true

module Security
  module DependencyFirewallPolicies
    class Rules
      include Enumerable

      def initialize(rules)
        @rules = (rules || []).map { |rule| Security::DependencyFirewallPolicies::Rule.by_type(rule) }
      end

      attr_reader :rules

      delegate :each, :[], :map, to: :rules
    end
  end
end
