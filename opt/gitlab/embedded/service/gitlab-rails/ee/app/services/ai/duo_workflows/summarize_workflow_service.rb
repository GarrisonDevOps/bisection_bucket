# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class SummarizeWorkflowService
      MAX_LOG_LENGTH_IN_CHARS = 50_000
      MAX_LOG_LINES = 500

      def initialize(workflow:)
        @workflow = workflow
      end

      def execute
        return unless workflow.user

        logs = fetch_logs
        return unless logs

        summarize_workflow(workflow, logs)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
        nil
      end

      private

      attr_reader :workflow

      def summarize_workflow(workflow, logs)
        prompt_message = ::Gitlab::Llm::AiMessage.new(
          request_id: SecureRandom.uuid,
          ai_action: 'summarize_duo_workflow',
          user: workflow.user,
          content: "",
          role: ::Gitlab::Llm::AiMessage::ROLE_USER,
          context: ::Gitlab::Llm::AiMessageContext.new(resource: workflow.resource_parent)
        )
        result = ::Gitlab::Llm::AiGateway::Completions::SummarizeDuoWorkflow.new(
          prompt_message,
          nil,
          { logs: logs }
        ).execute

        content = result&.[](:ai_message)&.content
        content.is_a?(String) ? content.strip.presence : nil
      end

      def fetch_logs
        failed_build = workflow.last_workload&.pipeline&.builds&.failed&.last
        failed_build&.trace&.raw(last_lines: MAX_LOG_LINES)&.last(MAX_LOG_LENGTH_IN_CHARS)
      end
    end
  end
end
