# frozen_string_literal: true

module Geo
  class ProjectWikiRepositoryReplicator < Gitlab::Geo::Replicator
    include ::Geo::RepositoryReplicatorStrategy

    def self.model
      ::Projects::WikiRepository
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Project Wiki Repository')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Project Wiki Repositories')
    end

    override :housekeeping_model_record
    def housekeeping_model_record
      # The ::Repositories::HousekeepingService and Wikis::GitGarbageCollectWorker
      # still rely on an instance of Wiki being the resource. We can remove this
      # when we update both to rely on the Projects::WikiRepository model.
      model_record.wiki
    end

    override :verify
    def verify
      # Historically some projects never had their wiki repos initialized;
      # this happens on project creation now. Let's initialize an empty repo
      # if it is not already there to allow them to be checksummed.
      model_record.create_wiki unless repository.exists?

      super
    end

    def repository
      model_record.repository
    end

    def org_migration_storage_ready?
      model_record.repository_storage != PLACEHOLDER_STORAGE
    end

    def assign_org_migration_storage!
      return unless ::Gitlab::Geo.org_migration_target?

      raise ::Geo::Errors::OrgMigrationRepositoryStorageNotReadyError unless org_migration_storage_ready?
    end
  end
end
