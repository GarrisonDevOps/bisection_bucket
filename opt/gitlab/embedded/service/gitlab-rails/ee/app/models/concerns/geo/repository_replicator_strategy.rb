# frozen_string_literal: true

module Geo
  module RepositoryReplicatorStrategy
    extend ActiveSupport::Concern

    include ::Geo::VerifiableReplicator
    include ::Geo::OrgMigrationRepositoryReplicatorConcern

    included do
      event ::Geo::ReplicatorEvents::EVENT_CREATED
      event ::Geo::ReplicatorEvents::EVENT_DELETED
      event ::Geo::ReplicatorEvents::EVENT_UPDATED
    end

    class_methods do
      def sync_timeout
        ::Geo::FrameworkRepositorySyncService::LEASE_TIMEOUT
      end

      def data_type
        'repository'
      end

      def data_type_title
        'Git'
      end

      def data_type_sort_order
        0
      end

      # Override this to disable git housekeeping
      def housekeeping_enabled?
        true
      end
    end

    # Called by Gitlab::Geo::Replicator#consume
    def consume_event_updated(**_params)
      with_record_not_found_handling do
        next unless in_replicables_for_current_secondary?

        # Race condition mitigation for mutable types.
        #
        # Within an updated event, we know that the source repo has changed. If a
        # sync is currently running, then *this* sync will be deduplicated (exit
        # early due to not being able to take the exclusive lease). In that case,
        # moving the registry to "pending" will block the currently running sync
        # from moving it to "synced". The running sync will then reschedule
        # itself to ensure a sync begins *after* the last known change to the
        # source repo. See `ReplicableRegistry#mark_synced_atomically`.
        #
        # We avoid saving when unpersisted since this should only occur if a
        # resource was just created but not yet replicated. And all saves after
        # the first one will raise the error `ActiveRecord::RecordNotUnique` anyway.
        registry.pending! if registry.persisted? && mutable?

        sync_repository
      end
    end

    # Called by Gitlab::Geo::Replicator#consume
    def consume_event_created(...)
      consume_event_updated(...)
    end

    # Called by Gitlab::Geo::Replicator#consume
    # Keep in mind that in_replicables_for_current_secondary? is not called here
    # This is because delete event should be handled by all the nodes
    # even if they're out of scope
    def consume_event_deleted(**params)
      replicate_destroy(params)
    end

    def replicate_destroy(params)
      Geo::RepositoryRegistryRemovalService.new(self, params).execute
    end

    def sync
      with_record_not_found_handling do
        Geo::FrameworkRepositorySyncService.new(self).execute
      end
    end
    alias_method :sync_repository, :sync # Backwards compatible with old docs, keep at least till 17.6
    alias_method :resync, :sync # Backwards compatible with old docs, keep at least till 17.6

    def enqueue_sync
      reschedule_sync
    end

    def reschedule_sync
      Geo::EventWorker.perform_async(
        replicable_name,
        ::Geo::ReplicatorEvents::EVENT_UPDATED,
        event_params
      )
    end

    # Schedules a verification job after a model record is created/updated
    #
    # Called by Gitlab::Geo::Replicator#geo_handle_after_(create|update)
    def after_verifiable_update
      verify_async if should_primary_verify_after_save?
    end

    # Called by Geo::FrameworkHousekeepingService#execute
    def before_housekeeping
      # no-op
    end

    # Called by Geo::FrameworkRepositorySyncService#execute_housekeeping
    #
    # Override this if you need to pass a different model instance to
    # the ::Repositories::HousekeepingService.
    #
    # @return [ApplicationRecord] instance
    def housekeeping_model_record
      model_record
    end

    def remote_url
      Gitlab::Geo.primary_node.repository_url(repository)
    end

    def jwt_authentication_header
      ::Gitlab::Geo::RepoSyncRequest.new(
        scope: repository.full_path
      ).authorization
    end

    def deleted_params
      event_params.merge(
        repository_storage: model_record.repository_storage,
        disk_path: model_record.repository.disk_path,
        full_path: model_record.repository.full_path
      )
    end

    # Returns a checksum of the repository refs as defined by Gitaly
    #
    # @return [String] checksum of the repository refs
    def calculate_checksum
      repository.checksum
    rescue Gitlab::Git::Repository::NoRepository => e
      log_error('Repository cannot be checksummed because it does not exist', e, replicable_params)

      raise
    end

    # Returns whether the Git repository exists
    #
    # Does a hard check because we are doing these checks for replication or
    # verification purposes, so we should not just trust the data in the DB if
    # we don't absolutely have to.
    #
    # @return [Boolean] whether the Git repository exists
    def resource_exists?
      repository.exists?
    end

    # Return whether it's immutable
    #
    # @return [Boolean] whether the replicable is immutable
    def immutable?
      false
    end
  end
end
