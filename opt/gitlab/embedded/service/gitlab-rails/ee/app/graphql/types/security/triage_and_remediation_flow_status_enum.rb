# frozen_string_literal: true

module Types
  module Security
    class TriageAndRemediationFlowStatusEnum < BaseEnum
      graphql_name 'TriageAndRemediationFlowStatus'
      description 'Whether the AI flow behind a triage and remediation capability is enabled'

      value 'AVAILABLE', value: 'available',
        description: 'Flow is enabled.',
        experiment: { milestone: '19.6' }

      value 'FLOW_NOT_ENABLED', value: 'flow_not_enabled',
        description: 'Flow is available but not enabled.',
        experiment: { milestone: '19.6' }

      value 'FLOW_UNAVAILABLE', value: 'flow_unavailable',
        description: 'Flow is not available.',
        experiment: { milestone: '19.6' }

      value 'FOUNDATIONAL_FLOWS_DISABLED', value: 'foundational_flows_disabled',
        description: 'Foundational flows are disabled.',
        experiment: { milestone: '19.6' }

      value 'NOT_APPLICABLE', value: 'not_applicable',
        description: 'Capability has no AI flow, so nothing needs to be configured.',
        experiment: { milestone: '19.6' }
    end
  end
end
