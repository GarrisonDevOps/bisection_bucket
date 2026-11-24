# frozen_string_literal: true

module Geo
  class ProjectRepositoryReplicator < Gitlab::Geo::Replicator
    include ::Geo::RepositoryReplicatorStrategy

    def self.model
      ::Project
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Project Repository')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Project Repositories')
    end

    def self.geo_project_repository_replication_v2_enabled?
      ::Feature.enabled?(:geo_project_repository_replication_v2, :instance)
    end

    def before_housekeeping
      return unless ::Gitlab::Geo.secondary_or_org_migration_target?

      create_object_pool_on_secondary if create_object_pool_on_secondary?
    end

    def repository
      model_record.repository
    end

    def org_migration_storage_ready?
      if self.class.geo_project_repository_replication_v2_enabled?
        model_record.shard_id.present?
      else
        model_record.repository_storage != PLACEHOLDER_STORAGE
      end
    end

    def assign_org_migration_storage!
      return unless ::Gitlab::Geo.org_migration_target?

      if self.class.geo_project_repository_replication_v2_enabled?
        assign_org_migration_storage_for_project_repository!
      else
        assign_org_migration_storage_for_project!
      end

      raise Geo::Errors::OrgMigrationRepositoryStorageNotReadyError unless org_migration_storage_ready?
    end

    def track_repository_after_org_migration!
      return unless ::Gitlab::Geo.org_migration_target?

      model_record.track_project_repository
    end

    # Ensure that a Project related event is always published, but a
    # ProjectRepository event is only published when the FF is enabled.
    def should_publish_replication_event?
      return false unless super
      return true if model_record.is_a?(::Project)

      self.class.geo_project_repository_replication_v2_enabled? && model_record.is_a?(::ProjectRepository)
    end

    private

    def assign_org_migration_storage_for_project!
      return unless model_record.repository_storage == PLACEHOLDER_STORAGE

      storage = ::Repository.pick_storage_shard
      model_record.update_column(:repository_storage, storage)

      # In project repository replication v1: model_record is the Project.
      # After updating repository_storage, we call cleanup to clear the
      # memoized @repository so subsequent sync uses the new storage.
      model_record.cleanup
    end

    def assign_org_migration_storage_for_project_repository!
      return if model_record.shard_id.present?

      storage = ::Repository.pick_storage_shard
      shard = ::Shard.by_name(storage)

      ApplicationRecord.transaction do
        model_record.update_column(:shard_id, shard.id)
        model_record.project.update_column(:repository_storage, storage)
      end

      # In project repository replication v2: model_record is the ProjectRepository.
      # We call reset on it to reload the DB attribute so shard_id is visible to
      # subsequent checks. For the project, we need both reset (to reload the
      # repository_storage attribute from DB) and cleanup (to clear the memoized
      # @repository so subsequent sync uses the new storage).
      model_record.reset
      model_record.project.reset
      model_record.project.cleanup
    end

    def pool_repository
      model_record.pool_repository
    end

    def create_object_pool_on_secondary
      Geo::CreateObjectPoolService.new(pool_repository).execute
    end

    def create_object_pool_on_secondary?
      return unless model_record.object_pool_missing?
      return unless pool_repository.source_project_repository&.exists?

      true
    end
  end
end
