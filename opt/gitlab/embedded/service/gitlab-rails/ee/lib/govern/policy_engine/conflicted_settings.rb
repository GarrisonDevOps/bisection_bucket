# frozen_string_literal: true

module Govern
  module PolicyEngine
    # Settings that two enforce policies demand different values for. Checked
    # per evaluation, because policies that did not overlap when saved can overlap later.
    class ConflictedSettings
      # @return [Hash{String => Hash{Integer => Object}}] each conflicted
      #   setting, with the value every writing policy demands for it
      def self.for(decisions:, policies:)
        new(decisions, policies).to_h
      end

      def initialize(decisions, policies)
        @decisions = decisions
        @policies = policies
      end

      def to_h
        demanded.select { |_setting, by_policy| disagree?(by_policy.values) }
      end

      private

      attr_reader :decisions, :policies

      # Compared with ==, as the engine compares numbers, so 1 and 1.0 agree.
      def disagree?(values)
        values.any? { |value| value != values.first }
      end

      def demanded
        decisions.each_with_object(Hash.new { |hash, key| hash[key] = {} }) do |decision, demands|
          policy = writing_policy(decision)
          next unless policy

          SettingValidationRule.for_policy(policy).each do |rule|
            demands[rule.setting][policy.id] = rule.expected
          end
        end
      end

      # The demand is the local rule, so an unmatched (compliant) or errored
      # decision still holds it. Two opposite boolean demands never match together.
      def writing_policy(decision)
        policy = policies[decision[:policy_id]]
        return unless policy&.mode_enforce?

        policy if decision[:actions].to_a.any? { |action| ActionCatalog.writes?(action[:action_type]) }
      end
    end
  end
end
