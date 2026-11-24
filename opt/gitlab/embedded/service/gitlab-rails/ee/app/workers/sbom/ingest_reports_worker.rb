# frozen_string_literal: true

module Sbom
  class IngestReportsWorker
    include ApplicationWorker

    deduplicate :until_executed, if_deduplicated: :reschedule_once
    idempotent!

    data_consistency :always

    worker_resource_boundary :cpu
    queue_namespace :sbom_reports
    feature_category :dependency_management

    # Ordered by index count -- an autovacuum on a heavily-indexed table is the one most likely
    # to be competing with ingestion for WAL bandwidth. The sbom lookup tables are left out:
    # 3-4 indexes each, and only genuinely new rows are written to them.
    defer_on_database_health_signal :gitlab_sec, [
      ::Sbom::Occurrence.table_name,
      ::Sbom::OccurrenceRef.table_name,
      ::Sbom::OccurrencesVulnerability.table_name
    ], 5.minutes

    def perform(pipeline_id)
      ::Ci::Pipeline.find_by_id(pipeline_id).try do |pipeline|
        ::Sbom::Ingestion::IngestReportsService.execute(pipeline)
      end
    end
  end
end
