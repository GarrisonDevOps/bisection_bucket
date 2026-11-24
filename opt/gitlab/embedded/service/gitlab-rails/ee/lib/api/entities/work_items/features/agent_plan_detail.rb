# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        # Content and feedback live in object storage, so only single work items expose them.
        class AgentPlanDetail < AgentPlan
          expose :content,
            documentation: { type: 'String', example: 'Step 1: Do the thing.' },
            expose_nil: true do |widget, options|
              ::Types::WorkItems::Widgets::AgentPlanType.track_agent_plan_read(widget, options[:current_user])
              widget.content
            end

          expose :readiness_score_feedback,
            documentation: {
              type: 'String', example: 'The plan covers all acceptance criteria.',
              desc: 'Markdown feedback explaining the readiness score. ' \
                'Requires the `workplan_score` feature flag for the current user.'
            },
            if: WORKPLAN_SCORE_ENABLED,
            expose_nil: true
        end
      end
    end
  end
end
