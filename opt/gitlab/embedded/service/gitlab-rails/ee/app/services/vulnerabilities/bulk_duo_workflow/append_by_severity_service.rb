# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflow
    class AppendBySeverityService < BaseService
      BATCH_SIZE = 1000

      def initialize(project:, workflow:, current_user:, finding_uuids: nil, severities: nil)
        super(project: project, current_user: current_user)

        @workflow = workflow
        @finding_uuids = finding_uuids
        @severities = severities
      end

      private

      attr_reader :workflow, :finding_uuids, :severities

      def perform
        return no_active_execution_error unless execution
        return already_started_error unless appendable?

        unless finding_uuids_belong_to_project?
          return ServiceResponse.error(
            message: _('One or more findings do not belong to the project'),
            reason: ERROR_REASONS[:forbidden]
          )
        end

        severities_to_process.each do |severity|
          findings_relation
            .by_severities(severity)
            .each_batch(of: BATCH_SIZE) do |batch|
            execution.append_to_stage!(
              stage: severity.to_sym,
              item_ids: batch.pluck_with_limit(BATCH_SIZE, :uuid)
            )
          end
        end

        ServiceResponse.success(message: _('Items appended'), payload: { execution: execution })
      end

      # Findings run as the execution's initiator, so only they may add findings, and only before it
      # starts. Otherwise another user's findings would run in, and be billed to, someone else's execution.
      def appendable?
        return false unless execution.status == ExecutionState::STATUS_CREATED

        initiator_id = execution.initiator_id
        initiator_id.nil? || initiator_id == current_user.id
      end

      def findings_relation
        relation = ::Vulnerabilities::Finding.by_projects(project.id)
        relation = relation.by_uuid(finding_uuids) if finding_uuids.present?

        relation
      end

      def severities_to_process
        stages = execution.stages.map { |stage| stage.fetch('name') }

        return stages unless severities.present?

        stages & severities.map(&:to_s)
      end

      def finding_uuids_belong_to_project?
        return true unless finding_uuids.present?

        findings_relation.count == finding_uuids.uniq.size
      end
    end
  end
end
