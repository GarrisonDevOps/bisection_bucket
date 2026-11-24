# frozen_string_literal: true

module Types
  module WorkItems
    module Widgets
      class AgentPlanInputType < BaseInputObject
        graphql_name 'WorkItemWidgetAgentPlanInput'

        argument :content, GraphQL::Types::String,
          required: false,
          description: 'Content of the agent plan.'

        argument :readiness_score, GraphQL::Types::Int,
          required: false,
          experiment: { milestone: '19.3' },
          description: copy_field_description(::Types::WorkItems::Widgets::AgentPlanType, :readiness_score)

        argument :readiness_score_feedback, GraphQL::Types::String,
          required: false,
          experiment: { milestone: '19.4' },
          description: 'Markdown feedback explaining the readiness score. ' \
            'Only available when the `workplan` feature flag is enabled.'
      end
    end
  end
end
