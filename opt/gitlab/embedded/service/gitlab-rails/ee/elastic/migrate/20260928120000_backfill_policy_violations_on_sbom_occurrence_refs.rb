# frozen_string_literal: true

class BackfillPolicyViolationsOnSbomOccurrenceRefs < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  batch_size 10_000
  batched!
  throttle_delay 15.seconds
  retry_on_failure

  DOCUMENT_TYPE = Sbom::OccurrenceRef

  def respect_limited_indexing?
    false
  end

  def item_to_preload
    { project: :namespace }
  end

  # Sbom::OccurrenceRef#es_parent raises on a row whose project is gone, failing the whole
  # batch inside track!. sbom_occurrence_refs is gitlab_sec and projects is gitlab_main_org,
  # so there is no foreign key and loose foreign key cleanup is asynchronous.
  def referenceable_documents(documents)
    referenceable, orphaned = documents.partition { |document| document.project.present? }

    if orphaned.any?
      log 'Skipped occurrence refs with no project',
        count: orphaned.size, project_ids: orphaned.map(&:project_id).uniq
    end

    referenceable
  end
end
