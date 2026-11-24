# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module RiskClassification
        # Fails the assessment a session leaves queued when the session ends
        # without submitting a result.
        module OnSessionEnded
          module_function

          def call(workflow:)
            # A retried session can be running again, and may still submit.
            return unless workflow.status_terminal?

            merge_request = workflow.merge_request
            assessment = merge_request&.risk_assessment
            # Checked again under the lock; this skips the query for sessions that submitted.
            return unless assessment&.queued?

            # rubocop:disable CodeReuse/ServiceClass -- a session hook is an entry point that
            # SessionLifecycleWorker calls, but foundational flows keep their hooks with the model.
            ::Gitlab::Duo::RiskAssessment::MarkFailedService.new(
              assessment,
              guard: ->(record) { record.queued? && !other_live_session?(workflow, merge_request) },
              log_message: 'Risk classification session ended without a result',
              log_context: { workflow_id: workflow.id, workflow_status: workflow.status_name.to_s }
            ).execute
            # rubocop:enable CodeReuse/ServiceClass
          end

          # Any live session can still submit, whichever one queued the row, so the last to end settles it.
          def other_live_session?(workflow, merge_request)
            ::Ai::DuoWorkflows::Workflow
              .for_merge_request(merge_request)
              .with_workflow_definition(workflow.workflow_definition)
              .where(execution_mode: [nil, :background]) # Client sessions never queue the row.
              .with_status(:created, :running)
              .id_not_in(workflow.id)
              .exists?
          end
        end
      end
    end
  end
end
