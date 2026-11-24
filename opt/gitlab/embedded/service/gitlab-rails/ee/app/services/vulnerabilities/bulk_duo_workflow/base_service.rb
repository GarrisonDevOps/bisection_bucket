# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    class BaseService < ::BaseProjectService
      include Gitlab::Allowable
      include Gitlab::Utils::StrongMemoize

      NOT_IMPLEMENTED_ERROR = "#{name} subclasses must implement #perform".freeze

      ERROR_REASONS = {
        already_started: :already_started,
        invalid_state: :invalid_state,
        not_found: :not_found,
        start_failed: :start_failed,
        forbidden: :forbidden,
        terminal_state: :terminal_state,
        cancel_failed: :cancel_failed
      }.freeze

      def execute
        authorize!

        perform
      end

      protected

      def workflow
        raise NotImplementedError, "#{self.class} subclasses must implement #workflow"
      end

      def execution
        ExecutionState.current(project_id: project.id, workflow: workflow)
      end
      strong_memoize_attr :execution

      def no_active_execution_error
        ServiceResponse.error(message: _('No active execution'), reason: ERROR_REASONS[:not_found])
      end

      def already_started_error
        ServiceResponse.error(message: _('Execution already started'), reason: ERROR_REASONS[:already_started])
      end

      private

      def perform
        raise NotImplementedError, NOT_IMPLEMENTED_ERROR
      end

      def authorize!
        raise Gitlab::Access::AccessDeniedError unless authorized?
      end

      def authorized?
        can?(current_user, :execute_vulnerability_duo_workflow, project)
      end
    end
  end
end
