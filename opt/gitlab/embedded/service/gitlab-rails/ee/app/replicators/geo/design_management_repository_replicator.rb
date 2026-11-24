# frozen_string_literal: true

module Geo
  class DesignManagementRepositoryReplicator < Gitlab::Geo::Replicator
    include ::Geo::RepositoryReplicatorStrategy

    def self.model
      DesignManagement::Repository
    end

    # @return [String] human-readable title.
    def self.replicable_title
      s_('Geo|Design Management Repository')
    end

    # @return [String] pluralized human-readable title.
    def self.replicable_title_plural
      s_('Geo|Design Management Repositories')
    end

    override :housekeeping_enabled?
    def self.housekeeping_enabled?
      false
    end

    def repository
      model_record.repository
    end

    override :verify
    def verify
      # Git repositories for designs are not created unless a design is added
      # but DesignManagement::Repository records were added for all projects
      # regardless of an existing git repo, in a migration.
      # See https://gitlab.com/gitlab-org/gitlab/-/merge_requests/116975
      # This results in verification failures.
      # TODO Remove empty repo creation once unnecessary DesignManagement::Repository
      # records are removed https://gitlab.com/gitlab-org/gitlab/-/issues/415551

      repository.create_if_not_exists

      super
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
