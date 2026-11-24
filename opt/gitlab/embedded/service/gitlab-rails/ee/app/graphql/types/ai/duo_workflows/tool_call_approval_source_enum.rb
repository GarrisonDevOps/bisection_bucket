# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      # Values name the proximate decision MECHANISM, not policy content or
      # authorship -- policy provenance is recorded separately in the audit
      # event's additional_details. Add values only for genuinely new mechanisms:
      # every new value breaks GraphQL validation for newer clients on older instances.
      class ToolCallApprovalSourceEnum < BaseEnum
        graphql_name 'DuoWorkflowToolCallApprovalSource'
        description 'Source of a Duo Workflow tool call approval decision, as reported ' \
          'by the client. Identifies the mechanism the client reports as having made ' \
          'the decision, not the policy that was evaluated or its author.'

        value 'USER_EXPLICIT', value: 'user_explicit',
          description: 'Explicit approval by a user action.',
          experiment: { milestone: '19.3' }
        value 'PRETOOLUSE_HOOK', value: 'pretooluse_hook',
          description: 'Approval granted automatically by a PreToolUse hook.',
          experiment: { milestone: '19.3' }
        value 'AUTO_MODE', value: 'auto_mode',
          description: 'Approval granted automatically by auto-mode.',
          experiment: { milestone: '19.3' }
        value 'PREAPPROVED_CONFIG', value: 'preapproved_config',
          description: 'Approval granted through a pre-approved tool or pattern configuration.',
          experiment: { milestone: '19.3' }
      end
    end
  end
end
