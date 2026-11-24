# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module CodeReview
      class CancelReviewService
        def initialize(merge_request:, current_user:)
          @merge_request = merge_request
          @current_user = current_user
        end

        def execute
          workflows = in_flight_workflows.to_a
          return if workflows.empty?

          workflows.each { |workflow| stop(workflow) }

          return if merge_request.duo_code_review_in_flight?

          merge_request.duo_code_review_progress_note&.destroy
        end

        private

        attr_reader :merge_request, :current_user

        def in_flight_workflows
          ::Ai::DuoWorkflows::Workflow
            .for_merge_request(merge_request)
            .with_workflow_definition(::Ai::Catalog::FoundationalFlow.code_review_v1.foundational_flow_reference)
            .without_messaging_sessions
            .with_status(:created, :running)
        end

        def stop(workflow)
          result = ::Ai::DuoWorkflows::UpdateWorkflowStatusService.new(
            workflow: workflow,
            status_event: 'stop',
            current_user: current_user
          ).execute

          return if result.success?

          ::Gitlab::AppLogger.warn(
            message: 'Duo Code Review flow not stopped',
            error_message: result.message,
            merge_request_id: merge_request.id,
            workflow_id: workflow.id
          )
        end
      end
    end
  end
end
