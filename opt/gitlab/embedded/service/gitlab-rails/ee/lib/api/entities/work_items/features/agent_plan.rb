# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class AgentPlan < Grape::Entity
          WORKPLAN_SCORE_ENABLED = ->(_widget, options) do
            ::Feature.enabled?(:workplan_score, options[:current_user])
          end

          expose :ai_planning_enabled?,
            as: :ai_planning_enabled,
            documentation: { type: 'Boolean', example: true }

          expose :has_content?,
            as: :has_content,
            documentation: { type: 'Boolean', example: true }

          expose :readiness_score,
            documentation: {
              type: 'Integer', example: 85,
              desc: 'Readiness score of the agent plan, from 0 to 100. ' \
                'Requires the `workplan_score` feature flag for the current user.'
            },
            if: WORKPLAN_SCORE_ENABLED,
            expose_nil: true
        end
      end
    end
  end
end
