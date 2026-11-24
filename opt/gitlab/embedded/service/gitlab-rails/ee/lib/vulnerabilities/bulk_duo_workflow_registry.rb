# frozen_string_literal: true

module Vulnerabilities
  module BulkDuoWorkflowRegistry
    extend self

    UNKNOWN_WORKFLOW = 'Unknown workflow: %s'

    RESOLVE_VULNERABILITY_IDS = ->(item_ids) do
      ::Vulnerabilities::Finding.by_uuid(item_ids).pluck_vulnerability_ids
    end

    WORKFLOWS = {
      ::Vulnerabilities::TriggerFalsePositiveDetectionWorkflowWorker::WORKFLOW_DEFINITION => {
        worker: ::Vulnerabilities::TriggerFalsePositiveDetectionWorkflowWorker,
        resolve_ids: RESOLVE_VULNERABILITY_IDS
      },
      ::Vulnerabilities::TriggerSecretDetectionFalsePositiveDetectionWorkflowWorker::WORKFLOW_DEFINITION => {
        worker: ::Vulnerabilities::TriggerSecretDetectionFalsePositiveDetectionWorkflowWorker,
        resolve_ids: RESOLVE_VULNERABILITY_IDS
      },
      ::Vulnerabilities::TriggerResolutionWorkflowWorker::WORKFLOW_DEFINITION => {
        worker: ::Vulnerabilities::TriggerResolutionWorkflowWorker,
        resolve_ids: ->(item_ids) { item_ids }
      }
    }.freeze

    def fetch(workflow)
      WORKFLOWS.fetch(workflow) do
        raise ArgumentError, format(UNKNOWN_WORKFLOW, workflow)
      end
    end
  end
end
