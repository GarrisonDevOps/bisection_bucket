# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class GenerateWorkflowTitleWorker
      include ApplicationWorker

      MAX_TITLE_LENGTH_IN_CHARS = 40
      # The model sometimes emits tool-call syntax (XML or a JSON tool_use block) instead of prose.
      UNUSABLE_TITLE_PREFIXES = ['<', '{', '[{'].freeze

      idempotent!
      feature_category :duo_agent_platform
      data_consistency :sticky

      def perform(workflow_id)
        workflow = ::Ai::DuoWorkflows::Workflow.find_by_id(workflow_id)
        return unless workflow

        title = GenerateWorkflowTitleService.new(workflow: workflow).execute
        return unless usable_title?(title)

        workflow.update!(title: title.truncate(MAX_TITLE_LENGTH_IN_CHARS))
      end

      private

      def usable_title?(title)
        title.present? && !title.lstrip.start_with?(*UNUSABLE_TITLE_PREFIXES)
      end
    end
  end
end
