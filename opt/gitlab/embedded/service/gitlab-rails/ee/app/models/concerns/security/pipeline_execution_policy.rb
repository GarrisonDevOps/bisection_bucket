# frozen_string_literal: true

module Security
  module PipelineExecutionPolicy
    POLICY_TYPE_NAME = 'Pipeline execution policy'

    def active_pipeline_execution_policies
      policy_limit = limit_service.pipeline_execution_policies_per_configuration_limit
      pipeline_execution_policy.select { |config| config[:enabled] }.first(policy_limit)
    end

    def active_pipeline_execution_policy_names(project)
      policy_scope_checker = ::Security::SecurityOrchestrationPolicies::PolicyScopeChecker.new(project: project)

      applicable_policies = active_pipeline_execution_policies
        .select { |policy| policy_scope_checker.policy_applicable?(policy, configuration: self) }

      return [] if applicable_policies.empty?

      applicable_policies.pluck(:name) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- not an ActiveRecord model and active_pipeline_execution_policies has limit
    end

    def pipeline_execution_policy
      policy_by_type(:pipeline_execution_policy).map.with_index do |policy, index|
        policy.merge(type: 'pipeline_execution_policy', policy_index: index)
      end
    end
  end
end
