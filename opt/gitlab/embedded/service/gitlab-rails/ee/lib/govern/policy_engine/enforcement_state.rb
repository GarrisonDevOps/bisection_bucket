# frozen_string_literal: true

module Govern
  module PolicyEngine
    # The state an enforcement row takes after one evaluation. Every value here
    # has to be one Govern::PolicyEnforcement can store.
    class EnforcementState
      # Compliant, either from the start or because a write restored it.
      COMPLETED = :completed
      # An open violation the policy does not, or cannot yet, fix.
      ACTIVE = :active
      # The policy could not be decided, or its action did not stick.
      FAILED = :failed

      ALL = [COMPLETED, ACTIVE, FAILED].freeze

      FAILED_OUTCOMES = %i[converge_ineffective converge_rejected converge_conflict audit_log_failed].freeze
      RESOLVED_OUTCOMES = %i[converged converge_noop].freeze

      def self.for(decision:, policy:, outcomes:)
        return FAILED if decision[:error]
        return COMPLETED unless decision[:matched]
        return ACTIVE unless policy.mode_enforce?
        return FAILED if outcomes.any? { |outcome| FAILED_OUTCOMES.include?(outcome[:outcome]) }
        return COMPLETED if outcomes.any? { |outcome| RESOLVED_OUTCOMES.include?(outcome[:outcome]) }

        ACTIVE
      end
    end
  end
end
