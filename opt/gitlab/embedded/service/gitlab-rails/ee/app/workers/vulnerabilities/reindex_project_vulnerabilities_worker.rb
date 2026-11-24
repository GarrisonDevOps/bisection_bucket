# frozen_string_literal: true

module Vulnerabilities
  # Re-indexes all of a project's vulnerability_reads into Elasticsearch without changing the
  # database rows. Used after an organization transfer so `as_indexed_json` recomputes the
  # `organization_id` field from the project's (already updated) namespace.
  class ReindexProjectVulnerabilitiesWorker
    include ApplicationWorker

    BATCH_SIZE = 100

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    data_consistency :sticky
    worker_resource_boundary :unknown

    feature_category :vulnerability_management

    def perform(project_id)
      # Re-check here too, in case Elasticsearch was turned off between enqueue and execution.
      return unless ::Search::Elastic::VulnerabilityIndexHelper.advanced_vulnerability_management_allowed?

      project = Project.find_by_id(project_id)
      return unless project

      project.vulnerability_reads.each_batch(of: BATCH_SIZE) do |batch|
        Vulnerabilities::BulkEsOperationService.new(batch).execute
      end
    end
  end
end
