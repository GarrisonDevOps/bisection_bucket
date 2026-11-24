# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module DeprecatedPropertiesChecker
      def deprecated_properties(policy)
        deprecated_properties = Set.new

        rules = policy[:rules] || []

        rules.each do |rule|
          deprecated_properties.add('match_on_inclusion') if rule.key?(:match_on_inclusion)
          deprecated_properties.add('newly_detected') if rule[:vulnerability_states]&.include?('newly_detected')
        end

        deprecated_properties.to_a
      end
    end
  end
end
