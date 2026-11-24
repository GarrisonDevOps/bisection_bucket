# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyTypeEnum < BaseEnum
      graphql_name 'PolicyType'

      value 'APPROVAL_POLICY',
        description: 'Approval policy.',
        value: :approval_policy

      value 'SCAN_EXECUTION_POLICY',
        description: 'Scan execution policy.',
        value: :scan_execution_policy

      value 'PIPELINE_EXECUTION_POLICY',
        description: 'Pipeline execution policy.',
        value: :pipeline_execution_policy

      value 'PIPELINE_EXECUTION_SCHEDULE_POLICY',
        description: 'Pipeline execution schedule policy.',
        value: :pipeline_execution_schedule_policy

      value 'VULNERABILITY_MANAGEMENT_POLICY',
        description: 'Vulnerability management policy.',
        value: :vulnerability_management_policy

      value 'DEPENDENCY_FIREWALL_POLICY',
        description: 'Dependency firewall policy.',
        value: :dependency_firewall_policy,
        experiment: { milestone: '19.0' }
    end
  end
end
