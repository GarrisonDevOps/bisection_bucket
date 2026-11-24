# frozen_string_literal: true

module Vulnerabilities
  class UpdateAscpAssociationsWorker
    include ApplicationWorker

    idempotent!
    deduplicate :until_executing, including_scheduled: true
    urgency :low
    data_consistency :delayed
    concurrency_limit -> { 200 }
    feature_category :static_application_security_testing
    defer_on_database_health_signal :gitlab_sec,
      [:vulnerability_occurrences, :vulnerability_finding_ascp_component_links], 5.minutes

    BATCH_SIZE = 1000
    DELAY_INTERVAL = 30.seconds.to_i

    def perform(project_id)
      project = Project.find_by_id(project_id)
      return unless project

      batches = 0

      Vulnerabilities::Finding.by_projects([project_id]).each_batch(of: BATCH_SIZE) do |batch, index|
        Vulnerabilities::UpdateAscpAssociationsBatchWorker.perform_in(
          index * DELAY_INTERVAL,
          project_id,
          batch.pluck_primary_key
        )

        batches += 1
      end

      log_extra_metadata_on_done(:batches_scheduled, batches)
    end
  end
end
