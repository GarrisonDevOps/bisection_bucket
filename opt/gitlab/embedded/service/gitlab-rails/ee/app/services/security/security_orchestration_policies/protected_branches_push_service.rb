# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ProtectedBranchesPushService < BaseProjectService
      def initialize(project:, ignore_warn_mode: false)
        super(project: project)
        @ignore_warn_mode = ignore_warn_mode
      end

      def execute
        PolicyBranchesService.new(project: project).scan_result_branches(rules)
      end

      private

      attr_reader :ignore_warn_mode

      def rules
        applicable_active_policies.each_with_object([]) do |policy, policies|
          policy.undeleted_approval_policy_rules.each do |rule|
            policies.push(rule.content.deep_symbolize_keys)
          end
        end
      end

      def applicable_active_policies
        policies = project
          .security_policies
          .type_approval_policy
          .enabled
          .prevent_pushing_and_force_pushing
          .preload_approval_policy_rules

        policies = policies.without_warn_mode unless ignore_warn_mode
        policies
      end
    end
  end
end
