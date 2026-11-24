# frozen_string_literal: true

module Types
  module SecurityOrchestration
    class PolicyViolationDetailsType < BaseObject # rubocop:disable Graphql/AuthorizeTypes -- Authorized via resolver
      graphql_name 'PolicyViolationDetails'
      description 'Represents the details of merge request approval policy violations.'

      field :policies,
        type: [Types::SecurityOrchestration::PolicyViolationInfoType],
        null: false,
        method: :violations,
        description: 'Information about policies that were violated.'

      field :violations_count,
        type: GraphQL::Types::Int,
        null: false,
        description: 'Total count of violations.'

      field :new_scan_finding,
        type: [Types::SecurityOrchestration::PolicyScanFindingViolationType],
        null: false,
        method: :new_scan_finding_violations,
        calls_gitaly: true,
        description: 'Represents the newly detected violations of `scan_finding` rules.'

      field :previous_scan_finding,
        type: [Types::SecurityOrchestration::PolicyScanFindingViolationType],
        null: false,
        method: :previous_scan_finding_violations,
        calls_gitaly: true,
        description: 'Represents the violations of `scan_finding` rules for previously existing vulnerabilities.'

      field :license_scanning,
        type: [Types::SecurityOrchestration::PolicyLicenseScanningViolationType],
        null: false,
        method: :license_scanning_violations,
        description: 'Represents the violations of `license_scanning` rules.'

      field :any_merge_request,
        type: [Types::SecurityOrchestration::PolicyAnyMergeRequestViolationType],
        null: false,
        method: :any_merge_request_violations,
        description: 'Represents the violations of `any_merge_request` rules.'

      field :errors,
        type: [Types::SecurityOrchestration::PolicyErrorType],
        null: false,
        description: 'Represents the policy errors.'

      field :comparison_pipelines,
        type: [Types::SecurityOrchestration::PolicyComparisonPipelineType],
        null: false,
        description: 'Represents the pipelines used for comparison in the policy evaluation.'
    end
  end
end
