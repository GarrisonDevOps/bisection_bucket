# frozen_string_literal: true

module PackageMetadata
  class LicensesSyncWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext
    include ExclusiveLeaseGuard
    include CronJitter

    # Must match LicenseV3SyncService::MAX_LEASE_LENGTH so StopSignal measures elapsed
    # time correctly. The v2 route gets its own length; see lease_timeout below.
    LEASE_TIMEOUT = 22.minutes

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
        config = licenses_config

        if config&.v3?
          LicenseV3SyncService.execute(lease: exclusive_lease)
        else
          # Only a v2 config ingests anything. A nil config means no purl types are
          # enabled, so nothing syncs and there is no clobbering to compensate for.
          drop_v3_license_checkpoints if config&.v2?
          SyncService.execute(data_type: 'licenses', lease: exclusive_lease)
        end
      end
    end

    private

    # A v2 run rewrites each package's whole license tuple, dropping the expression
    # IDs v3 wrote, and resuming v3 from its old bookmark would never restore them.
    # Dropping the bookmarks makes the next v3 run start from the /all snapshot.
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/616368
    def drop_v3_license_checkpoints
      checkpoints = Checkpoint.for_dataset('licenses', SyncConfiguration::VERSION_FORMAT_V3)
      return unless checkpoints.exists?

      log_extra_metadata_on_done(:v3_license_checkpoints_deleted, checkpoints.delete_all)
    end

    # Reads the config, not the flag: offline installs stay on v2 even when the flag
    # is on. One format for all licenses configs, so the `first` decides; nil when no
    # purl types are enabled, which must read as neither v2 nor v3.
    def licenses_config
      SyncConfiguration.configs_for('licenses').first
    end

    def should_run?
      return false unless feature_available?
      return false if Rails.env.development? && ENV.fetch('PM_SYNC_IN_DEV', 'false') != 'true'

      true
    end

    # license_scanning is Ultimate-only; Premium reaches the sync through the
    # dependency firewall, which consumes this data.
    # https://gitlab.com/gitlab-org/gitlab/-/work_items/630259
    def feature_available?
      ::License.feature_available?(:license_scanning) ||
        ::Security::DependencyFirewall::Availability.instance_configurable?
    end

    # Each route's StopSignal derives elapsed time from its own max_lease_length
    # minus the lease TTL, so a route handed a lease of another length gets a
    # silently wrong budget. Branches the same way perform does.
    def lease_timeout
      licenses_config&.v3? ? LEASE_TIMEOUT : SyncService::MAX_LEASE_LENGTH
    end
  end
end
