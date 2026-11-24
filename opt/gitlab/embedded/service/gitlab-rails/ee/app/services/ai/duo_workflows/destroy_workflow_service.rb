# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class DestroyWorkflowService
      include ::Gitlab::Allowable

      def initialize(workflow:, current_user:)
        @workflow = workflow
        @current_user = current_user
      end

      def execute
        unless can?(current_user, :delete_duo_workflow, workflow)
          return ::ServiceResponse.error(message: 'User not authorized to delete workflow')
        end

        # Capture details before destroy since the record will be frozen after
        scope = workflow.project || workflow.namespace
        target_details = "#{workflow.workflow_definition || 'Unknown'} session #{workflow.id}"

        if workflow.destroy
          audit_deletion(scope, target_details)
          ::ServiceResponse.success
        else
          ::ServiceResponse.error(message: workflow.errors.full_messages)
        end
      end

      private

      attr_reader :workflow, :current_user

      def audit_deletion(scope, target_details)
        audit_context = {
          name: 'duo_session_deleted',
          author: current_user,
          scope: scope,
          target: workflow,
          target_details: target_details,
          message: 'Deleted Duo session'
        }

        ::Gitlab::Audit::Auditor.audit(audit_context)
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e)
      end
    end
  end
end
