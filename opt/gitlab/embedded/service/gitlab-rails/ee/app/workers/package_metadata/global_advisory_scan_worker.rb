# frozen_string_literal: true

module PackageMetadata
  class GlobalAdvisoryScanWorker
    include Gitlab::EventStore::Subscriber

    data_consistency :sticky
    feature_category :software_composition_analysis
    urgency :throttled
    deduplicate :until_executed
    idempotent!
    concurrency_limit -> { 10 }

    # Ordered by index count -- every index is maintained on write, so heavily-indexed tables are
    # the ones whose autovacuum competes with CVS ingestion for WAL bandwidth. The lower-index
    # tables in the IngestCvsSliceService write path are left out to keep the stop signal targeted.
    defer_on_database_health_signal :gitlab_sec, [
      ::Vulnerabilities::Read.table_name,
      ::Vulnerabilities::Finding.table_name,
      ::Vulnerability.table_name,
      ::Vulnerabilities::Identifier.table_name,
      ::Vulnerabilities::FindingIdentifier.table_name
    ], 5.minutes

    def handle_event(event)
      advisory = Advisory.with_affected_packages.find_by_id(event.data[:advisory_id])

      if advisory.nil?
        return logger.error(structured_payload(message: 'Advisory not found.', advisory_id: event.data[:advisory_id]))
      end

      AdvisoryScanService.execute(advisory)
    end
  end
end
