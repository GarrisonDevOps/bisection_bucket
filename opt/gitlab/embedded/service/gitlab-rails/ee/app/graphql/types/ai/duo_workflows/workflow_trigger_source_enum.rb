# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class WorkflowTriggerSourceEnum < BaseEnum
        graphql_name 'DuoWorkflowTriggerSource'
        description 'Kind of initiator that started a Duo Workflow session.'

        value 'HUMAN', value: 'human', description: 'Session started by a user action.'
        value 'SYSTEM', value: 'system', description: 'Session started by the system without a user.'
        value 'SCHEDULED', value: 'scheduled', description: 'Session started by a flow schedule.'
        value 'VERIFICATION', value: 'verification', description: 'Session started by a functional verification check.'
        value 'FLOW', value: 'flow', description: 'Session started by another session.'
      end
    end
  end
end
