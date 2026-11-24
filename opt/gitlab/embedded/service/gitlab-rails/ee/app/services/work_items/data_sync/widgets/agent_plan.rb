# frozen_string_literal: true

module WorkItems
  module DataSync
    module Widgets
      class AgentPlan < Base
        def after_save_commit
          source_plan = work_item.agent_plan
          return unless source_plan

          rewritten_content = MarkdownContentRewriterService.new(
            current_user,
            source_plan,
            :content,
            work_item.namespace,
            target_work_item.namespace
          ).execute

          rewritten_feedback = MarkdownContentRewriterService.new(
            current_user,
            source_plan,
            :readiness_score_feedback,
            work_item.namespace,
            target_work_item.namespace
          ).execute

          ::WorkItems::AgentPlan.create!(
            work_item: target_work_item,
            content: rewritten_content[:content],
            readiness_score_feedback: rewritten_feedback[:readiness_score_feedback],
            ai_planning_enabled: source_plan.ai_planning_enabled,
            readiness_score: source_plan.readiness_score
          )
        end

        def post_move_cleanup
          work_item.agent_plan&.destroy!
        end
      end
    end
  end
end
