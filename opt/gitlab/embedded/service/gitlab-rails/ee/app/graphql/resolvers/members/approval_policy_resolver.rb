# frozen_string_literal: true

module Resolvers
  module Members
    class ApprovalPolicyResolver < BaseResolver
      include ResolvesOrchestrationPolicy
      include ConstructApprovalPolicies

      type Types::SecurityOrchestration::ApprovalPolicyType, null: true

      def resolve
        policies = object.dependent_security_policies
          .preload_approval_policy_rules
          .preload_configuration_namespace_and_project
          .select { |policy| authorized_to_read_policy?(policy) }
          .map do |policy|
            config = policy.security_orchestration_policy_configuration

            policy.to_policy_hash.merge({
              config: config,
              project: config.project,
              namespace: config.namespace,
              inherited: false
            })
          end
        construct_scan_result_policies(policies)
      end

      def container
        object.namespace
      end

      private

      def authorized_to_read_policy?(policy)
        config = policy.security_orchestration_policy_configuration
        Ability.allowed?(current_user, :read_security_orchestration_policies, config.source)
      end
    end
  end
end
