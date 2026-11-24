# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class GenerateWorkflowTitleService
      def initialize(workflow:)
        @workflow = workflow
      end

      def execute
        return unless workflow.user
        return unless workflow.goal.present?

        generate_title
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, workflow_id: workflow.id)
        nil
      end

      private

      attr_reader :workflow

      def generate_title
        prompt_message = ::Gitlab::Llm::AiMessage.new(
          request_id: SecureRandom.uuid,
          ai_action: 'generate_duo_workflow_title',
          user: workflow.user,
          content: "",
          role: ::Gitlab::Llm::AiMessage::ROLE_USER,
          context: ::Gitlab::Llm::AiMessageContext.new(resource: workflow.resource_parent)
        )
        result = ::Gitlab::Llm::AiGateway::Completions::GenerateDuoWorkflowTitle.new(
          prompt_message,
          nil,
          { context: workflow.goal, definition: workflow.workflow_definition }
        ).execute

        content = result&.[](:ai_message)&.content
        content.is_a?(String) ? content.strip.presence : nil
      end
    end
  end
end
