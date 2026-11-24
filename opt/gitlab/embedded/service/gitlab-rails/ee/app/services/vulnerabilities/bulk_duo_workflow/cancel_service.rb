# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    class CancelService < BaseService
      def initialize(project:, workflow:, current_user:)
        super(project: project, current_user: current_user)

        @workflow = workflow
      end

      private

      attr_reader :workflow

      def perform
        return no_active_execution_error unless execution

        case execution.cancel!
        when ExecutionState::STATUS_CANCELLED
          ServiceResponse.success(message: _('Execution cancelled'), payload: { execution: execution })
        when *ExecutionState::TERMINAL_STATES
          ServiceResponse.error(
            message: _('Execution already in terminal state'),
            reason: ERROR_REASONS[:terminal_state]
          )
        when ExecutionState::RESULT_NOT_FOUND
          no_active_execution_error
        else
          ServiceResponse.error(message: _('Unable to cancel execution'), reason: ERROR_REASONS[:cancel_failed])
        end
      end
    end
  end
end
