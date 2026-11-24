# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class AgentPlanGenerationStatusEnum < Types::BaseEnum
        graphql_name 'WorkItemAgentPlanGenerationStatus'
        description 'Status of the asynchronous workplan generation flow for a work item.'

        value 'NOT_STARTED', value: :not_started,
          description: 'No workplan generation flow has run for the work item.'
        value 'GENERATING', value: :generating,
          description: 'Indicates a workplan generation flow is in progress.'
        value 'NEEDS_INPUT', value: :needs_input,
          description: 'Indicates the flow is waiting for user input.'
        value 'COMPLETED', value: :completed,
          description: 'Indicates the flow finished successfully.'
        value 'CANCELED', value: :canceled,
          description: 'Indicates the flow was canceled by a user.'
        value 'FAILED', value: :failed,
          description: 'Indicates the flow ended without completing.'
      end
    end
  end
end
