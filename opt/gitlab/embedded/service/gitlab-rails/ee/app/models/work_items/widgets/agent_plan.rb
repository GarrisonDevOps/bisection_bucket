# frozen_string_literal: true

module WorkItems
  module Widgets
    class AgentPlan < Base
      def self.required_user_ability
        :update_work_item
      end

      # Status of a work item's most recent workplan generation run, `:not_started` without one.
      #
      # `:completed` describes the run, not the work item: the agent writes plan content
      # through a separate update that can fail to land.
      #
      # @param latest_workflow [Ai::DuoWorkflows::Workflow, nil] see `latest_workplan_workflows_for`
      # @return [Symbol]
      def self.generation_status_for(latest_workflow)
        latest_workflow&.progress_status || :not_started
      end

      # Most recent workplan generation workflow for each given work item, in a single query.
      # Work items without a workflow are absent from the result.
      #
      # @param work_item_ids [Array<Integer>]
      # @return [Hash<Integer, Ai::DuoWorkflows::Workflow>]
      def self.latest_workplan_workflows_for(work_item_ids)
        ::Ai::DuoWorkflows::Workflow
          .with_workflow_definition(::Ai::Catalog::FoundationalFlow.workplan_v1.reference)
          .for_issue(work_item_ids)
          .latest_per_issue
          .index_by(&:issue_id)
      end

      delegate :content, :content_html, :readiness_score, :readiness_score_feedback, :readiness_score_feedback_html,
        :updated_at,
        to: :agent_plan_record, allow_nil: true

      def ai_planning_enabled?
        work_item.ai_planning_enabled?
      end

      # The scoring step runs at the end of the workplan flow and writes the score last, so an
      # empty score alone can't tell "still scoring" from "failed" or "never ran". A running flow
      # wins over a stored score, as it is about to replace it. A failed or canceled flow only counts
      # as a scoring failure once it wrote a plan, since the plan is written before the score.
      #
      # @param latest_workflow [Ai::DuoWorkflows::Workflow, nil] latest workplan generation workflow
      # @return [Symbol] :evaluated, :evaluating, :failed, :canceled or :not_evaluated
      def readiness_score_status(latest_workflow)
        return :evaluating if latest_workflow&.progress_status == :generating
        return :evaluated unless readiness_score.nil?
        return :not_evaluated if latest_workflow.nil?
        return :canceled if latest_workflow.stopped? && plan_written_during?(latest_workflow)
        return :failed if latest_workflow.failed? && plan_written_during?(latest_workflow)

        :not_evaluated
      end

      def workplan_questions(current_user)
        strong_memoize_with(:workplan_questions, current_user) do
          ::Ai::DuoWorkflows::WorkplanQuestions.new(work_item, current_user)
        end
      end

      def latest_workflow
        ::Ai::DuoWorkflows::Workflow
          .with_workflow_definition(::Ai::Catalog::FoundationalFlow.workplan_v1.reference)
          .for_issue(work_item.id)
          .ordered_by_id_desc
          .first
      end

      def has_content?
        agent_plan_record&.has_content? || false
      end

      private

      # Database columns only: reading `content` is an object storage round-trip per work item.
      # A plan last saved before the run started comes from an earlier run or a manual edit.
      def plan_written_during?(workflow)
        return false unless agent_plan_record&.has_content?

        agent_plan_record.updated_at > workflow.created_at
      end

      def agent_plan_record
        work_item.agent_plan
      end
    end
  end
end
