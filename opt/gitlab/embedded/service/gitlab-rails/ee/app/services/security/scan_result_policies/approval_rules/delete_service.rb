# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module ApprovalRules
      class DeleteService
        def initialize(project:, security_policy:, approval_policy_rules:)
          @project = project
          @security_policy = security_policy
          @approval_policy_rules = approval_policy_rules
        end

        def execute
          return if approval_policy_rules.empty?

          security_policy.delete_approval_policy_rules_for_project(project, approval_policy_rules)
        end

        private

        attr_reader :project, :security_policy, :approval_policy_rules
      end
    end
  end
end
