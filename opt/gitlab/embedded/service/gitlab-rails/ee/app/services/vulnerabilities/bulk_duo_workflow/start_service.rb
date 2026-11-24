# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    class StartService < BaseService
      include Gitlab::InternalEvents::ServiceTracking

      track_internal_event(
        'start_vulnerability_bulk_duo_workflow',
        on: :success,
        additional_properties: ->(result) {
          execution = result.payload[:execution]

          {
            label: execution.workflow.to_s,
            value: execution.progress[:total]
          }
        }
      )

      def initialize(project:, workflow:, current_user:)
        super(project: project, current_user: current_user)

        @workflow = workflow
      end

      private

      attr_reader :workflow

      def perform
        return no_active_execution_error unless execution

        case execution.start!
        when ExecutionState::STATUS_RUNNING
          item_ids = execution.next_batch

          execution.start_processing!(item_ids)

          config = ::Vulnerabilities::BulkDuoWorkflowRegistry.fetch(execution.workflow)
          config[:resolve_ids].call(item_ids).each do |id|
            config[:worker].perform_async(id, execution.execution_id)
          end

          ServiceResponse.success(
            message: _('Execution started'),
            payload: { execution: execution, item_ids: item_ids }
          )
        when ExecutionState::STATUS_ALREADY_RUNNING
          already_started_error
        when *ExecutionState::TERMINAL_STATES, ExecutionState::RESULT_INVALID
          ServiceResponse.error(message: _('Execution cannot be started'), reason: ERROR_REASONS[:invalid_state])
        when ExecutionState::RESULT_NOT_FOUND
          no_active_execution_error
        else
          ServiceResponse.error(message: _('Unable to start execution'), reason: ERROR_REASONS[:start_failed])
        end
      end

      def tracking_project_source(_result)
        project
      end
    end
  end
end
