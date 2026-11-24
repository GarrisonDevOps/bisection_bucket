# frozen_string_literal: true

module EE
  module Types
    module TodoTargetEnum
      extend ActiveSupport::Concern

      prepended do
        value 'EPIC', value: 'Epic', description: 'An Epic.'
        value 'USER', value: 'User', description: 'User.'
        value 'VULNERABILITY', value: 'Vulnerability', description: 'Vulnerability.'
        value 'COMPLIANCE_VIOLATION', value: 'ComplianceManagement::Projects::ComplianceViolation',
          description: 'Project Compliance Violation.'
        value 'DUO_WORKFLOW', value: 'Ai::DuoWorkflows::Workflow',
          description: 'Duo Workflow session.'
      end
    end
  end
end
