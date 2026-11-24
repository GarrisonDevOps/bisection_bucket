# frozen_string_literal: true

module Vulnerabilities
  module WorkflowTrackable
    include Gitlab::InternalEventsTracking

    def perform(*args)
      item_id, execution_id = args
      return super unless execution_id

      finding = finding_from_args(item_id)
      return super unless finding

      execution = execution_from_args(finding, execution_id)
      return super unless execution

      if execution.cancel_requested?
        execution.mark_cancelled!([finding.uuid])
        cancel_pending_findings(execution, finding.project)

        track_terminal_execution(execution, finding)

        return
      end

      self.bulk_initiator_id = execution.initiator_id

      result = super

      _transition, next_item_ids = execution.mark_completed!([finding.uuid])

      enqueue_items(execution, next_item_ids)

      track_terminal_execution(execution, finding)

      result
    end

    def handle_retry_exhaustion(job)
      item_id, execution_id = job['args']
      return unless execution_id

      finding = finding_from_args(item_id)
      return unless finding

      execution = execution_from_args(finding, execution_id)
      return unless execution

      _transition, next_item_ids = execution.mark_failed!([finding.uuid])

      enqueue_items(execution, next_item_ids)
      track_terminal_execution(execution, finding)
    end

    private

    attr_accessor :bulk_initiator_id

    def cancel_pending_findings(execution, project)
      return execution.cancel_pending! if Feature.enabled?(:batch_bulk_duo_workflow_cancel_cleanup, project)

      execution.pending_ids_by_stage.each do |stage_order, item_ids|
        item_ids.each_slice(execution.batch_size) do |batch|
          execution.mark_cancelled!(batch, stage_order: stage_order)
        end
      end
    end

    def execution_from_args(finding, execution_id)
      return unless execution_id

      ::Vulnerabilities::BulkDuoWorkflow::ExecutionState.fetch(
        execution_id: execution_id,
        project_id: finding.project_id,
        workflow: self.class::WORKFLOW_DEFINITION
      )
    end

    def finding_from_args(...)
      return super if defined?(super)

      raise NotImplementedError, "#{self.class} must implement #finding_from_args"
    end

    def enqueue_items(execution, item_ids)
      return if item_ids.blank?

      config = ::Vulnerabilities::BulkDuoWorkflowRegistry.fetch(execution.workflow)

      config[:resolve_ids].call(item_ids).each do |id|
        config[:worker].perform_async(id, execution.execution_id)
      end
    end

    def track_terminal_execution(execution, finding)
      status = execution.status
      return unless ::Vulnerabilities::BulkDuoWorkflow::ExecutionState::TERMINAL_STATES.include?(status)

      properties = {
        label: execution.workflow.to_s,
        property: status.to_s,
        value: execution.progress[:total],
        duration: (execution.ended_at - execution.started_at).round
      }

      return unless execution.claim_finish_event?

      track_internal_event(
        'finish_vulnerability_bulk_duo_workflow',
        project: finding.project,
        additional_properties: properties
      )
    end
  end
end
