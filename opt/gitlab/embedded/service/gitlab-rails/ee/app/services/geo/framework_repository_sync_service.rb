# frozen_string_literal: true

#
# This service handles Git repository synchronization from primary to secondary Geo sites
# using the Self-Service Framework.
#
# Usage:
#   Called by Geo::SyncWorker for background syncs and Geo::EventWorker for event-driven
#   syncs after repository updates.
#
# Exclusive Lease:
#   Uses a 3-hour exclusive lease (via ExclusiveLeaseGuard) to prevent concurrent sync
#   operations on the same repository, which could cause race conditions and unnecessary
#   I/O load due to extra syncs.
#
# Orphaned Keys:
#   If the sync process is killed uncleanly, the lease may not be released in the ensure block,
#   blocking syncs for up to 3 hours until expiration.
#
# For detailed information about the repository sync flow, exclusive lease mechanism,
# and troubleshooting orphaned lease keys, see doc/development/geo/repository_sync.md
#
require 'securerandom'

module Geo
  class FrameworkRepositorySyncService
    include ExclusiveLeaseGuard
    include ::Gitlab::Geo::LogHelpers
    include Delay

    attr_reader :replicator

    delegate :registry, to: :replicator

    # This timeout matches the expected Git fetch timeout documented in Geo troubleshooting docs for 'context deadline exceeded' errors.
    # See https://docs.gitlab.com/administration/geo/replication/troubleshooting/synchronization_verification/#error-fetch-remote-signal-terminated-context-deadline-exceeded-at-exactly-3-hours
    LEASE_TIMEOUT    = 3.hours
    LEASE_KEY_PREFIX = 'geo_sync_ssf_service'

    def initialize(replicator)
      @replicator = replicator
      @new_repository = false
    end

    def repository
      replicator.repository
    end

    def execute
      try_obtain_lease do
        log_info("Started #{replicable_name} sync")

        sync_repository

        log_info("Finished #{replicable_name} sync")
      end

      # Must happen after releasing lease to avoid race condition where the new
      # job cannot obtain the lease.
      do_reschedule_sync if reschedule_sync?
    end

    def sync_repository
      @skip_housekeeping = false
      replicator.assign_org_migration_storage!
      start_registry_sync!
      fetch_repository
      mark_sync_as_successful
      replicator.track_repository_after_org_migration!
    rescue Geo::Errors::OrgMigrationRepositoryStorageNotReadyError
      mark_repository_storage_not_ready
      @skip_housekeeping = true
    rescue Gitlab::Git::Repository::NoRepository
      mark_missing_on_primary
      @skip_housekeeping = true
    rescue Gitlab::Shell::Error, Gitlab::Git::BaseError => e
      fail_registry_sync!('Error syncing repository', e)
    ensure
      expire_repository_caches
      execute_housekeeping
    end

    def lease_key
      @lease_key ||= "#{LEASE_KEY_PREFIX}:#{replicable_name}:#{replicator.model_record.id}"
    end

    def lease_timeout
      LEASE_TIMEOUT
    end

    private

    def fetch_repository
      log_info("Trying to fetch #{replicable_name}")

      if repository.exists?
        fetch_geo_mirror
      else
        clone_geo_mirror
        @new_repository = true
      end

      update_root_ref
    end

    def current_node
      ::Gitlab::Geo.current_node
    end

    # Updates an existing repository using JWT authentication mechanism
    #
    # @param [Repository] target_repository specify a different temporary repository (default: current repository)
    def fetch_geo_mirror(target_repository: repository)
      # Fetch the repository, using a JWT header for authentication
      target_repository.fetch_as_mirror(replicator.remote_url, forced: true, http_authorization_header: replicator.jwt_authentication_header)
    end

    # Clone a Geo repository using JWT authentication mechanism
    #
    # @param [Repository] target_repository specify a different temporary repository (default: current repository)
    def clone_geo_mirror(target_repository: repository)
      target_repository.clone_as_mirror(replicator.remote_url, http_authorization_header: replicator.jwt_authentication_header)
    end

    def mark_sync_as_successful(missing_on_primary: false)
      log_info("Marking #{replicable_name} sync as successful")

      registry = replicator.registry
      registry.missing_on_primary = missing_on_primary
      persisted = registry.synced!

      set_reschedule_sync unless persisted

      log_info("Finished #{replicable_name} sync",
        download_time_s: download_time_in_seconds)
    end

    def mark_missing_on_primary
      log_info('Repository is not found, marking it as successfully synced')
      mark_sync_as_successful(missing_on_primary: true)
    end

    def mark_repository_storage_not_ready
      message = 'Waiting for project repository sync to assign a storage'
      log_info(message)
      replicator.registry.failed!(message: message)
    end

    def start_registry_sync!
      log_info("Marking #{replicable_name} sync as started")

      registry.start!
    end

    def fail_registry_sync!(message, error)
      log_error(message, error)

      registry = replicator.registry
      registry.failed!(message: message, error: error)
    end

    def download_time_in_seconds
      (Time.current.to_f - registry.last_synced_at.to_f).round(3)
    end

    def repository_storage
      replicator.model_record.repository_storage
    end

    def new_repository?
      @new_repository
    end

    def ensure_repository
      repository.create_if_not_exists
    end

    def expire_repository_caches
      log_info('Expiring caches for repository')
      repository.after_sync
    end

    def execute_housekeeping
      return unless replicator.class.housekeeping_enabled?
      return if skip_housekeeping?

      task = new_repository? ? :gc : nil
      service = ::Repositories::HousekeepingService.new(replicator.housekeeping_model_record, task)
      service.increment!

      return if task.nil? && !service.needed?

      service.execute do
        replicator.before_housekeeping
      end
    rescue ::Repositories::HousekeepingService::LeaseTaken
      # best-effort
    end

    def set_reschedule_sync
      @reschedule_sync = true
    end

    def reschedule_sync?
      @reschedule_sync
    end

    def skip_housekeeping?
      @skip_housekeeping
    end

    def do_reschedule_sync
      log_info("Reschedule the sync because an updated event was processed during the sync")

      replicator.reschedule_sync
    end

    def replicable_name
      replicator.replicable_name
    end

    def update_root_ref
      authorization = ::Gitlab::Geo::RepoSyncRequest.new(
        scope: repository.full_path
      ).authorization

      repository.update_root_ref(replicator.remote_url, authorization)
    end
  end
end
