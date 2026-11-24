# frozen_string_literal: true

module Security
  class StoreScansWorker # rubocop:disable Scalability/IdempotentWorker
    include ApplicationWorker

    data_consistency :always

    worker_resource_boundary :cpu
    sidekiq_options retry: 5
    include SecurityScansQueue

    # Lease contention backs off 1, 2, 4, 8 and 16 minutes, which covers the 30 minute lease TTL.
    # nil keeps the Sidekiq default delay for all other errors.
    sidekiq_retry_in do |count, exception|
      (2**count).minutes.to_i if exception.is_a?(Security::StoreGroupedScansService::LeaseTakenError)
    end

    feature_category :vulnerability_management

    defer_on_database_health_signal :gitlab_sec, [
      ::Security::Scan.table_name,
      ::Security::Finding.table_name,
      ::Security::FindingEnrichment.table_name
    ], 1.minute

    def self.defer_on_database_health_signal?
      # rubocop:disable Gitlab/FeatureFlagWithoutActor -- fleet-wide throttle, no actor in scope
      Feature.enabled?(:defer_store_scans_on_database_health)
      # rubocop:enable Gitlab/FeatureFlagWithoutActor
    end

    def perform(pipeline_id)
      ::Ci::Pipeline.find_by_id(pipeline_id).try do |pipeline|
        break unless pipeline.project.can_store_security_reports?

        Security::StoreScansService.execute(pipeline, lease_owner: jid)
      end
    end
  end
end
