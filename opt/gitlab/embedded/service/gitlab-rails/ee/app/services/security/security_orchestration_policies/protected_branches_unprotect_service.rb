# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ProtectedBranchesUnprotectService < ProtectedBranchesPushService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        super.merge(policy_branches)
      end

      private

      def policy_branches
        rules.filter_map { |rule| rule[:branches] }.flatten
      end
    end
  end
end
