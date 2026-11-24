# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowStatusGroupEnum < BaseEnum
        graphql_name 'DuoWorkflowStatusGroup'
        description 'The status group of the flow session.'

        ::Ai::DuoWorkflows::Workflow::GROUPED_STATUSES.each_key do |group|
          value group.to_s.upcase, value: group,
            description: "Flow sessions with a status group of #{group}."
        end
      end
    end
  end
end
