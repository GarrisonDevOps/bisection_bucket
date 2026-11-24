# frozen_string_literal: true

module ConstructSecurityPolicies
  extend ActiveSupport::Concern
  include ConstructScanExecutionPolicies
  include ConstructApprovalPolicies
  include ConstructVulnerabilityManagementPolicies
  include ConstructPipelineExecutionPolicies
  include ConstructPipelineExecutionSchedulePolicies
  include ConstructDependencyFirewallPolicies

  def construct_security_policies(policies)
    policies.filter_map do |policy|
      construct_security_policy(policy)
    end
  end

  def construct_security_policy(policy)
    case policy[:type]
    when "pipeline_execution_policy"
      construct_pipeline_execution_policy(policy, true)
    when "pipeline_execution_schedule_policy"
      construct_pipeline_execution_schedule_policy(policy, true)
    when "scan_execution_policy"
      construct_scan_execution_policy(policy, true)
    when "scan_result_policy", "approval_policy"
      construct_scan_result_policy(policy, true)
    when "vulnerability_management_policy"
      construct_vulnerability_management_policy(policy, true)
    when "dependency_firewall_policy"
      construct_dependency_firewall_policy(policy, true)
    end
  end
end
