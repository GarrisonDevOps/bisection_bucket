# frozen_string_literal: true

module Types
  module Security
    class AnalyzerSourceEnum < Types::BaseEnum
      graphql_name 'AnalyzerSourceEnum'
      description 'Source of the build that ran the analyzer'

      value 'SCAN_EXECUTION_POLICY',
        value: 'scan_execution_policy',
        description: 'Job source is a scan execution policy.'

      value 'PIPELINE_EXECUTION_POLICY',
        value: 'pipeline_execution_policy',
        description: 'Job source is a pipeline execution policy.'

      value 'SECURITY_SCAN_PROFILES',
        value: 'security_scan_profiles',
        description: 'Job source is a security scan profile.'

      value 'PIPELINE_EXECUTION_POLICY_SCHEDULE',
        value: 'pipeline_execution_policy_schedule',
        description: 'Job source is a scheduled pipeline execution policy.'

      value 'SECURITY_ORCHESTRATION_POLICY',
        value: 'security_orchestration_policy',
        description: 'Job source is a security orchestration policy.'

      value 'ON_DEMAND_DAST_SCAN',
        value: 'ondemand_dast_scan',
        description: 'Job source is an on-demand DAST scan.'

      value 'ON_DEMAND_DAST_VALIDATION',
        value: 'ondemand_dast_validation',
        description: 'Job source is an on-demand DAST site profile validation.'

      value 'YML',
        value: 'yml',
        description: 'Job source is defined or included in .gitlab-ci.yml.'
    end
  end
end
