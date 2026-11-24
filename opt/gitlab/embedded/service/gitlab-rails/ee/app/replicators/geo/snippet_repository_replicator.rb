# frozen_string_literal: true

module Geo
  class SnippetRepositoryReplicator < Gitlab::Geo::Replicator
    include ::Geo::RepositoryReplicatorStrategy

    def self.model
      ::SnippetRepository
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Snippet Repository')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Snippet Repositories')
    end

    override :housekeeping_enabled?
    def self.housekeeping_enabled?
      false
    end

    def repository
      model_record.repository
    end

    def org_migration_storage_ready?
      model_record.shard_id.present?
    end

    def assign_org_migration_storage!
      return unless ::Gitlab::Geo.org_migration_target?

      if model_record.shard_id.blank?
        shard = ::Shard.by_name(::Repository.pick_storage_shard)
        model_record.update_column(:shard_id, shard.id)
        model_record.reset
      end

      raise ::Geo::Errors::OrgMigrationRepositoryStorageNotReadyError unless org_migration_storage_ready?
    end
  end
end
