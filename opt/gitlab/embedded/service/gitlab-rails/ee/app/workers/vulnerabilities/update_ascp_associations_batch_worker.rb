# frozen_string_literal: true

module Vulnerabilities
  class UpdateAscpAssociationsBatchWorker
    include ApplicationWorker

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    urgency :low
    data_consistency :delayed
    concurrency_limit -> { 200 }
    feature_category :static_application_security_testing
    defer_on_database_health_signal :gitlab_sec,
      [:vulnerability_occurrences, :vulnerability_finding_ascp_component_links], 5.minutes

    def perform(project_id, finding_ids)
      project = Project.find_by_id(project_id)
      return unless project

      response = Security::Ascp::BulkSetComponentService.new(
        project: project,
        finding_ids: finding_ids
      ).execute

      log_extra_metadata_on_done(:stats, response.payload.merge(batch_size: finding_ids.size))
    end
  end
end
