# frozen_string_literal: true

module Security
  module DependencyFirewallPolicy
    POLICY_TYPE_NAME = 'Dependency firewall policy'

    def active_dependency_firewall_policies
      return unless ::Security::DependencyFirewall::Availability.access_enabled?(source)

      policy_limit = limit_service.dependency_firewall_policies_per_configuration_limit
      dependency_firewall_policy.select { |config| config[:enabled] }.first(policy_limit)
    end

    def dependency_firewall_policy
      policy_by_type(:dependency_firewall_policy)
    end

    def applicable_dependency_firewall_policies_for_project(project)
      strong_memoize_with(:applicable_dependency_firewall_policies_for_project, project) do
        policy_scope_checker = ::Security::SecurityOrchestrationPolicies::PolicyScopeChecker.new(project: project)
        active_dependency_firewall_policies.select do |policy|
          policy_scope_checker.policy_applicable?(policy, configuration: self)
        end
      end
    end
  end
end
