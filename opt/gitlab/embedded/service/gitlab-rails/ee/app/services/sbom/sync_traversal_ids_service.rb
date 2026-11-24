# frozen_string_literal: true

module Sbom
  class SyncTraversalIdsService
    include Gitlab::ExclusiveLeaseHelpers

    BATCH_SIZE = 100

    # Typical job finishes in a few seconds
    LEASE_TTL = 1.minute

    # This may be waiting on an SBoM ingestion job.
    # 10 retries at 6 seconds each will allow 95% of jobs to acquire a lease
    # without raising FailedToObtainLockError. When waiting for exceptionally long jobs,
    # we'll allow the job to raise and be retried by sidekiq.
    LEASE_TRY_AFTER = 6.seconds

    def self.execute(project_id)
      new(project_id).execute
    end

    def initialize(project_id)
      @project_id = project_id
    end

    def execute
      return unless project

      in_lock(lease_key, ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER) { update_sbom_occurrences }

      reindex_occurrence_refs
    end

    private

    attr_reader :project_id

    def lease_key
      Sbom::Ingestion.project_lease_key(project_id)
    end

    def project
      @project ||= Project.find_by_id(project_id)
    end

    def update_sbom_occurrences
      project.sbom_occurrences.each_batch(of: BATCH_SIZE) do |batch|
        batch.update_all(traversal_ids: project.namespace.traversal_ids)
      end
    end

    def reindex_occurrence_refs
      return unless ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed?

      ::Sbom::OccurrenceRef.by_project(project_id).each_batch(of: BATCH_SIZE) do |batch|
        ::Sbom::BulkEsOperationService.new(batch).execute
      end
    end
  end
end
