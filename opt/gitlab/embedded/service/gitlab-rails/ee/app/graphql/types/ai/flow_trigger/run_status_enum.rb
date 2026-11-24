# frozen_string_literal: true

module Types
  module Ai
    module FlowTrigger
      class RunStatusEnum < BaseEnum
        graphql_name 'AiFlowTriggerRunStatus'
        description 'Status of a flow trigger run.'

        value 'PENDING', value: :pending, description: 'Run has been created and has not started.'
        value 'RUNNING', value: :running, description: 'Run is in progress.'
        value 'AWAITING_INPUT', value: :awaiting_input, description: 'Run is paused or waiting for input or approval.'
        value 'SUCCEEDED', value: :succeeded, description: 'Run finished successfully.'
        value 'FAILED', value: :failed, description: 'Run failed.'
        value 'CANCELED', value: :canceled, description: 'Run was stopped before it finished.'
      end
    end
  end
end
