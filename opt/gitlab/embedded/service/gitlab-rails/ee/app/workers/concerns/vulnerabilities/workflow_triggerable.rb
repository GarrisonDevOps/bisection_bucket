# frozen_string_literal: true

module Vulnerabilities
  module WorkflowTriggerable
    extend ActiveSupport::Concern

    BULK_INITIATOR_PERMISSIONS = %i[execute_vulnerability_duo_workflow duo_workflow].freeze

    private

    def resolve_workflow_user(vulnerability, project)
      initiator_id = bulk_initiator_id
      return resolve_bulk_initiator(initiator_id, vulnerability, project) if initiator_id

      author = vulnerability.author

      return author if Ability.allowed?(author, :duo_workflow, project)

      Gitlab::AppLogger.info(
        message: 'Vulnerability author does not have duo_workflow permission',
        vulnerability_id: vulnerability.id,
        project_id: project.id,
        author_id: author&.id
      )

      nil
    end

    # Overridden by Vulnerabilities::WorkflowTrackable for bulk runs.
    def bulk_initiator_id
      nil
    end

    # Never falls back to the author, as that would bill the author for a run they did not start.
    def resolve_bulk_initiator(initiator_id, vulnerability, project)
      context = { vulnerability_id: vulnerability.id, project_id: project.id, initiator_id: initiator_id }
      initiator = User.find_by_id(initiator_id)

      unless initiator
        Gitlab::AppLogger.info(message: 'Bulk workflow initiator not found', **context)

        return
      end

      # The initiator must still be allowed to start the bulk run, as checked by the mutation, and to run Duo workflows.
      missing_permission = BULK_INITIATOR_PERMISSIONS.detect do |permission|
        !Ability.allowed?(initiator, permission, project)
      end
      return initiator unless missing_permission

      Gitlab::AppLogger.info(
        message: 'Bulk workflow initiator does not have permission to run the workflow',
        missing_permission: missing_permission,
        **context
      )

      nil
    end

    def log_no_eligible_user(vulnerability, project)
      initiator_id = bulk_initiator_id
      context = { vulnerability_id: vulnerability.id, project_id: project.id }

      if initiator_id
        Gitlab::AppLogger.error(
          message: 'No eligible user found for vulnerability workflow, ' \
            'bulk initiator is not eligible',
          initiator_id: initiator_id,
          **context
        )
      else
        Gitlab::AppLogger.error(
          message: 'No eligible user found for vulnerability workflow, ' \
            'author lacks duo_workflow permission',
          **context
        )
      end
    end

    def log_service_account_not_found(vulnerability, consumer, workflow_name)
      Gitlab::AppLogger.error(
        message: "Service account not found for #{workflow_name}, " \
          'the service account may have been deleted',
        vulnerability_id: vulnerability.id,
        project_id: vulnerability.project_id,
        consumer_id: consumer.id,
        workflow_definition: self.class::WORKFLOW_DEFINITION
      )
    end
  end
end
