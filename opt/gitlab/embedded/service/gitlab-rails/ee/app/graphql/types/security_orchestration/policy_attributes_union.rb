# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyAttributesUnion < BaseUnion
      graphql_name 'PolicyAttributesUnion'
      description 'Represents specific policy types. Its fields depend on the policy type.'

      possible_types Types::SecurityOrchestration::ApprovalPolicyAttributesType,
        Types::SecurityOrchestration::ScanExecutionPolicyAttributesType,
        Types::SecurityOrchestration::PipelineExecutionPolicyAttributesType,
        Types::Security::VulnerabilityManagementPolicyAttributesType,
        Types::SecurityOrchestration::PipelineExecutionScheduledPolicyAttributesType,
        Types::Security::DependencyFirewallPolicyAttributesType

      def self.resolve_type(object, _context)
        case object[:type]
        when 'approval_policy'
          Types::SecurityOrchestration::ApprovalPolicyAttributesType
        when 'scan_execution_policy'
          Types::SecurityOrchestration::ScanExecutionPolicyAttributesType
        when 'pipeline_execution_policy'
          Types::SecurityOrchestration::PipelineExecutionPolicyAttributesType
        when 'pipeline_execution_schedule_policy'
          Types::SecurityOrchestration::PipelineExecutionScheduledPolicyAttributesType
        when 'vulnerability_management_policy'
          Types::Security::VulnerabilityManagementPolicyAttributesType
        when 'dependency_firewall_policy'
          Types::Security::DependencyFirewallPolicyAttributesType
        end
      end
    end
  end
end
