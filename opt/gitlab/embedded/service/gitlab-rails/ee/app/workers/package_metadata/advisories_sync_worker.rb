# frozen_string_literal: true

module PackageMetadata
  class AdvisoriesSyncWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext
    include ExclusiveLeaseGuard
    include CronJitter
    include Gitlab::Utils::StrongMemoize

    data_consistency :always
    feature_category :software_composition_analysis
    urgency :low

    idempotent!
    sidekiq_options retry: false
    worker_has_external_dependencies!

    # `jittered` is false on the cron tick and true on the delayed re-enqueue.
    def perform(jittered = false)
      return unless should_run?

      return self.class.perform_in(jitter_offset, true) if apply_jitter? && !jittered

      try_obtain_lease do
        config = advisories_config

        if config&.v3?
          AdvisoryV3SyncService.execute(lease: exclusive_lease)
        else
          # Only a v2 config ingests anything. A nil config means no purl types are
          # enabled, so nothing syncs and there is nothing to compensate for.
          drop_v3_advisory_checkpoints if config&.v2?
          SyncService.execute(data_type: 'advisories', lease: exclusive_lease)
        end
      end
    end

    private

    # Reads the config, not the flag, so an offline v2 root stays on v2. Memoized so the
    # lease size and the route come from the same read; nil means no purl types enabled.
    def advisories_config
      SyncConfiguration.configs_for('advisories').first
    end
    strong_memoize_attr :advisories_config

    # When falling back from v3 to v2 we want to ensure that if we go back to v3 we
    # start with a fresh sync, so every field v2 does not write is populated again
    # from scratch. The advisory upsert rewrites every column of a row it touches, so
    # a field only v3 populates returns to NULL on a v2 run.
    def drop_v3_advisory_checkpoints
      checkpoints = Checkpoint.for_dataset('advisories', SyncConfiguration::VERSION_FORMAT_V3)
      return unless checkpoints.exists?

      log_extra_metadata_on_done(:v3_advisory_checkpoints_deleted, checkpoints.delete_all)
    end

    def should_run?
      return false unless feature_available?
      return false if Rails.env.development? && ENV.fetch('PM_SYNC_IN_DEV', 'false') != 'true'

      true
    end

    # dependency_scanning is Ultimate-only; Premium reaches the sync through the
    # dependency firewall, which consumes this data.
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/630259
    def feature_available?
      ::License.feature_available?(:dependency_scanning) ||
        ::Security::DependencyFirewall::Availability.instance_configurable?
    end

    # StopSignal infers elapsed time by subtracting the lease TTL from the service's
    # own max_lease_length, so a lease of another length gives it a false baseline.
    # Taken from each service rather than restated here, so the two cannot drift.
    def lease_timeout
      advisories_config&.v3? ? AdvisoryV3SyncService::MAX_LEASE_LENGTH : SyncService::MAX_LEASE_LENGTH
    end
  end
end
