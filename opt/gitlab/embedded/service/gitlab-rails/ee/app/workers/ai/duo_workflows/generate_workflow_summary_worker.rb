# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class GenerateWorkflowSummaryWorker
      include ApplicationWorker

      idempotent!
      feature_category :duo_agent_platform
      data_consistency :sticky

      def perform(workflow_id)
        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        return unless workflow
        # The summary is an LLM reading of the job log, stored where customers can read it.
        return if workflow.metadata_content_retention?

        summary = SummarizeWorkflowService.new(workflow: workflow).execute
        workflow.update!(summary: summary.truncate(1024)) if summary.present?
      end
    end
  end
end
