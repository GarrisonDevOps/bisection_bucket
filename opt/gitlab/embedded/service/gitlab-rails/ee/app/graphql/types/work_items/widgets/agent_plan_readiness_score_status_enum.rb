# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class AgentPlanReadinessScoreStatusEnum < Types::BaseEnum
        graphql_name 'WorkItemAgentPlanReadinessScoreStatus'
        description 'Status of the readiness score evaluation for a work item.'

        value 'EVALUATED', value: :evaluated,
          description: 'Indicates a readiness score is available.'
        value 'EVALUATING', value: :evaluating,
          description: 'Indicates the workplan flow is running and a new score is expected.'
        value 'FAILED', value: :failed,
          description: 'Indicates the flow failed after the plan was written, before a score was saved.'
        value 'CANCELED', value: :canceled,
          description: 'Indicates the flow was canceled before a score was saved.'
        value 'NOT_EVALUATED', value: :not_evaluated,
          description: 'Indicates there is no score and the flow is not running.'
      end
    end
  end
end
