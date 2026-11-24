# frozen_string_literal: true

module Geo
  class GroupWikiRepositoryReplicator < Gitlab::Geo::Replicator
    include ::Geo::RepositoryReplicatorStrategy

    def self.model
      ::GroupWikiRepository
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Group Wiki Repository')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Group Wiki Repositories')
    end

    override :housekeeping_enabled?
    def self.housekeeping_enabled?
      false
    end

    override :verify
    def verify
      # See https://gitlab.com/gitlab-org/gitlab/-/issues/426571
      unless repository.exists?
        log_error(
          "Git repository of group wiki was not found. To avoid verification error, creating empty Git repository",
          nil,
          {
            group_wiki_repository_id: model_record.id,
            group_id: model_record.group_id
          }
        )

        model_record.create_wiki
      end

      super
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
