# frozen_string_literal: true

module Geo
  # Concern for repository replicators that participate in org migration.
  #
  # During org migration, PG logical replication copies rows to the target
  # cell with sentinel storage values (NULL shard_id for v2, or
  # 'reset_storage' for v1). Replicators that include this concern can
  # detect these sentinels, assign real storage, and track the repository
  # after a successful sync.
  #
  # By default all methods are safe no-ops. Replicators that participate
  # in org migration should override them with their specific logic.
  module OrgMigrationRepositoryReplicatorConcern
    # Sentinel value used as repository_storage by PG logical replication (v1).
    PLACEHOLDER_STORAGE = 'reset_storage'

    # Whether the repository has been assigned a real storage.
    #
    # @return [Boolean] true if storage is ready (default: true).
    def org_migration_storage_ready?
      true
    end

    # Assigns real storage to a repository that still has a sentinel value.
    #
    # @return [void]
    def assign_org_migration_storage!
      # no-op by default
    end

    # Tracks the repository record after a successful migration sync.
    #
    # @return [void]
    def track_repository_after_org_migration!
      # no-op by default
    end
  end
end
