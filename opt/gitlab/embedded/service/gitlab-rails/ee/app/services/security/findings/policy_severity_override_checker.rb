# frozen_string_literal: true

module Security
  module Findings
    class PolicySeverityOverrideChecker
      include Gitlab::Utils::StrongMemoize

      SEVERITY_ORDER = %i[info low medium high critical].freeze
      SEVERITY_RANK = SEVERITY_ORDER.each_with_index.to_h.freeze

      def initialize(project)
        @project = project
      end

      def check_with_policy(target)
        candidates = policies_with_severity_override.filter_map do |policy, action|
          next unless rules_for_policy(policy).any? { |rule| rule.match?(target) }

          [calculate_severity(target.severity, action), policy]
        end

        best_severity, best_policy = candidates.max_by { |severity, _| SEVERITY_RANK[severity] || -1 }

        return if best_severity.nil? || best_severity.to_s == target.severity.to_s

        { severity: best_severity.to_s, policy: best_policy }
      end

      def policies_present?
        policies_with_severity_override.any?
      end

      private

      attr_reader :project

      def policies_with_severity_override
        policies.map do |policy|
          [policy, policy.vulnerability_management_policy.actions.first]
        end
      end
      strong_memoize_attr :policies_with_severity_override

      def policies
        project
          .vulnerability_management_policies
          .severity_override_policies
          .including_rules
      end
      strong_memoize_attr :policies

      def rules_for_policy(policy)
        policy.vulnerability_management_policy_rules.select(&:type_detected?)
      end

      def calculate_severity(current_severity, action)
        current_sym = current_severity.to_sym

        case action.severity_override_operation
        when 'set'
          action.severity_override_value.to_sym
        when 'increase'
          step_severity(current_sym, 1)
        when 'decrease'
          step_severity(current_sym, -1)
        else
          current_sym
        end
      end

      def step_severity(current_sym, delta)
        idx = SEVERITY_ORDER.index(current_sym)
        return current_sym unless idx

        SEVERITY_ORDER[(idx + delta).clamp(0, SEVERITY_ORDER.size - 1)]
      end
    end
  end
end
