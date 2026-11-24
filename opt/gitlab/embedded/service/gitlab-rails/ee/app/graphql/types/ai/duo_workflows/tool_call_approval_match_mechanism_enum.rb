# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class ToolCallApprovalMatchMechanismEnum < BaseEnum
        graphql_name 'DuoWorkflowToolCallApprovalMatchType'
        description 'Mechanism that resolved a stored Duo Workflow tool call approval.'

        value 'EXACT_HASH', value: ::Ai::DuoWorkflows::Workflow::ToolCallApprovals::MATCH_TYPE_EXACT_HASH,
          description: 'Tool call matched a previously approved call by exact argument hash.',
          experiment: { milestone: '19.3' }
        value 'PATTERN', value: ::Ai::DuoWorkflows::Workflow::ToolCallApprovals::MATCH_TYPE_PATTERN,
          description: 'Tool call matched a stored glob pattern.',
          experiment: { milestone: '19.3' }
      end
    end
  end
end
