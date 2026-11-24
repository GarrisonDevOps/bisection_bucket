# frozen_string_literal: true

module Geo
  class ProjectRepositoryRegistry < Geo::BaseRegistry
    include ::Geo::ReplicableRegistry
    include ::Geo::VerifiableRegistry
    extend ::Gitlab::Geo::LogHelpers

    belongs_to :project, class_name: 'Project'

    def self.model_class
      ::Project
    end

    def self.model_foreign_key
      :project_id
    end

    def self.model_updated_last
      :last_repository_updated_at
    end

    # Returns whether the project repository is out-of-date on this site
    #
    # The return value must be cached in RequestStore to ensure a consistent request
    #
    # @return [Boolean] whether the project repository is out-of-date on this site
    def self.repository_out_of_date?(project_id, synchronous_request_required = false)
      return false unless ::Gitlab::Geo.secondary_with_primary?

      cache_key = "geo_repository_out_of_date:#{project_id}:#{synchronous_request_required}"

      Gitlab::SafeRequestStore.fetch(cache_key) do
        registry = find_or_initialize_by(project_id: project_id)
        registry.repository_out_of_date?(synchronous_request_required)
      end
    end

    # @return [Boolean] whether the project repository is out-of-date on this site
    def repository_out_of_date?(synchronous_request_required = false)
      return out_of_date("registry doesn't exist") unless persisted?
      return out_of_date("project doesn't exist") if project.nil?
      return out_of_date("sync failed") if failed?

      unless project.last_repository_updated_at
        return up_to_date("there is no timestamp for the latest change to the repo")
      end

      return out_of_date("it has never been synced") unless last_synced_at
      return out_of_date("not verified yet") unless verification_succeeded?

      # Relatively expensive check
      return synchronous_pipeline_check if synchronous_request_required

      best_guess_with_local_information
    end

    # @return [Boolean] whether the latest pipeline refs are present on the secondary
    def synchronous_pipeline_check
      secondary_pipeline_refs = project.repository.list_refs(['refs/pipelines/']).collect(&:name)
      primary_pipeline_refs = ::Gitlab::Geo.primary_pipeline_refs(project_id)
      missing_refs = primary_pipeline_refs - secondary_pipeline_refs

      if !missing_refs.empty?
        out_of_date("secondary is missing pipeline refs", missing_refs: missing_refs.take(30))
      else
        up_to_date("secondary has all pipeline refs")
      end
    end

    # Current limitations:
    #
    # - We assume last_repository_updated_at is a timestamp of the latest change
    # - But last_repository_updated_at touches are throttled within Event::REPOSITORY_UPDATED_AT_INTERVAL minutes
    # - And Postgres replication is asynchronous so it may be lagging behind
    #
    # @return [Boolean] whether the latest change is replicated
    def best_guess_with_local_information
      last_updated_at = project.last_repository_updated_at

      if last_synced_at <= last_updated_at
        out_of_date("last successfully synced before latest change",
          last_synced_at: last_synced_at, last_updated_at: last_updated_at)
      else
        up_to_date("last successfully synced after latest change",
          last_synced_at: last_synced_at, last_updated_at: last_updated_at)
      end
    end

    def out_of_date(reason, details = {})
      details
        .merge!(replicator.replicable_params)
        .merge!({
          class: self.class.name,
          reason: reason
        })

      log_info("out-of-date", details)

      true
    end

    def up_to_date(reason, details = {})
      details
        .merge!(replicator.replicable_params)
        .merge!({
          class: self.class.name,
          reason: reason
        })

      log_info("up-to-date", details)

      false
    end
  end
end
