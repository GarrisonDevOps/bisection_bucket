# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowDropReasonEnum < BaseEnum
        graphql_name 'DuoWorkflowDropReason'
        description 'Reason a GitLab Duo Agent Platform session was failed.'

        ::Ai::DuoWorkflows::Workflow::DROP_REASONS.each do |reason|
          value reason.upcase, value: reason, description: "The session was failed with the reason `#{reason}`."
        end
      end
    end
  end
end
