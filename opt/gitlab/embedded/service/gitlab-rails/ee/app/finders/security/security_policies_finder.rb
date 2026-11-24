# frozen_string_literal: true

module Security
  class SecurityPoliciesFinder
    def initialize(actor, policy_configurations)
      @actor = actor
      @policy_configurations = policy_configurations
    end

    def execute
      initial_value = {
        scan_execution_policies: [],
        scan_result_policies: [],
        pipeline_execution_policies: [],
        pipeline_execution_schedule_policies: [],
        vulnerability_management_policies: []
      }

      policy_configurations
        .select { |config| authorized_to_read_policy_configuration?(config) }
        .each_with_object(initial_value) do |config, policies|
          policies.merge!(policies_with_relationship_information(config)) { |_, old_val, new_val| old_val + new_val }
        end
    end

    private

    attr_reader :actor, :policy_configurations

    def authorized_to_read_policy_configuration?(config)
      Ability.allowed?(actor, :read_security_orchestration_policies, config.source)
    end

    def policies_with_relationship_information(config)
      {
        scan_execution_policies: merge_with_default_config(config, config.scan_execution_policy),
        scan_result_policies: merge_with_default_config(config, config.scan_result_policies),
        pipeline_execution_policies: merge_with_default_config(config, config.pipeline_execution_policy),
        pipeline_execution_schedule_policies:
          merge_with_default_config(config, config.pipeline_execution_schedule_policy),
        vulnerability_management_policies: merge_with_default_config(config, config.vulnerability_management_policy)
      }
    end

    def merge_with_default_config(config, policies)
      policy_config = {
        config: config,
        project: config.project,
        namespace: config.namespace,
        inherited: false,
        csp: config.designated_as_csp?
      }

      policies.map { |policy| policy.merge(policy_config) }
    end
  end
end
