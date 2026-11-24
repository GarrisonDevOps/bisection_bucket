# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    class FindOrCreateService < BaseService
      def initialize(project:, workflow:, stages:, current_user:, batch_size: ExecutionState::BATCH_SIZE, metadata: {})
        super(project: project, current_user: current_user)

        @workflow = workflow
        @stages = stages
        @batch_size = batch_size
        @metadata = metadata
      end

      private

      attr_reader :workflow, :stages, :batch_size, :metadata

      def perform
        return success(_('Execution already exists'), execution, created: false) if execution

        execution = ExecutionState.create!(
          project_id: project.id,
          workflow: workflow,
          stages: stages,
          batch_size: batch_size,
          metadata: metadata.merge(initiator_id: current_user.id)
        )

        success(_('Execution created'), execution, created: true)
      end

      def success(message, execution, created:)
        ServiceResponse.success(
          message: message,
          payload: { execution: execution, created: created }
        )
      end
    end
  end
end
