# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowStatusEnum < BaseEnum
        graphql_name 'DuoWorkflowStatus'
        description 'The status of the workflow.'

        ::Ai::DuoWorkflows::Workflow.state_machine.states.each do |status|
          value status.name.to_s.upcase, value: status.value, description: "The workflow is #{status.name}."
        end
      end
    end
  end
end
