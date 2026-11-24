# frozen_string_literal: true

module PackageMetadata
  class CveEnrichmentSyncWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- there is no relevant metadata to add to logs
    include ExclusiveLeaseGuard

    # Must match SyncService::CVE_ENRICHMENT_MAX_LEASE_LENGTH so StopSignal
    # measures elapsed time correctly.
    LEASE_TIMEOUT = SyncService::CVE_ENRICHMENT_MAX_LEASE_LENGTH

    data_consistency :always
    feature_category :software_composition_analysis
    urgency :low

    idempotent!
    sidekiq_options retry: false
    worker_has_external_dependencies!

    def perform
      return unless should_run?

      try_obtain_lease do
        SyncService.execute(data_type: 'cve_enrichment', lease: exclusive_lease)

        if ::License.feature_available?(:security_orchestration_policies)
          Security::SyncFindingEnrichmentWorker.perform_async
        end
      end
    end

    private

    def should_run?
      return false unless ::License.feature_available?(:dependency_scanning)
      return false if Rails.env.development? && ENV.fetch('PM_SYNC_IN_DEV', 'false') != 'true'

      true
    end

    def lease_timeout
      LEASE_TIMEOUT
    end
  end
end
