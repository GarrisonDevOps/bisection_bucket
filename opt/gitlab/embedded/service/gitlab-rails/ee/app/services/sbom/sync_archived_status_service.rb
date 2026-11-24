# frozen_string_literal: true

module Sbom
  class SyncArchivedStatusService
    include Gitlab::Utils::StrongMemoize
    include Gitlab::ExclusiveLeaseHelpers

    BATCH_SIZE = 100

    # Typical job finishes in a few seconds
    LEASE_TTL = 1.minute

    # This may be waiting on an SBoM ingestion job.
    # 10 retries at 6 seconds each will allow 95% of jobs to acquire a lease
    # without raising FailedToObtainLockError. When waiting for exceptionally long jobs,
    # we'll allow the job to raise and be retried by sidekiq.
    LEASE_TRY_AFTER = 6.seconds

    def initialize(project_id)
      @project_id = project_id
    end

    def execute
      return unless project

      in_lock(lease_key, ttl: LEASE_TTL, sleep_sec: LEASE_TRY_AFTER) { update_archived_status }

      reindex_occurrence_refs
    end

    private

    attr_reader :project_id

    def update_archived_status
      project.sbom_occurrences.each_batch(of: BATCH_SIZE) do |batch|
        batch.update_all(archived: project.self_or_ancestors_archived?)
      end
    end

    def reindex_occurrence_refs
      return unless ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed?

      ::Sbom::OccurrenceRef.by_project(project_id).each_batch(of: BATCH_SIZE) do |batch|
        ::Sbom::BulkEsOperationService.new(batch).execute
      end
    end

    def project
      Project.find_by_id(project_id)
    end
    strong_memoize_attr :project

    def lease_key
      Sbom::Ingestion.project_lease_key(project_id)
    end
  end
end
