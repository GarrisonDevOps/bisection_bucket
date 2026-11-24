# frozen_string_literal: true

class BackfillSbomOccurrenceRefsIndex < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  # Superseded by 20260928120000 BackfillPolicyViolationsOnSbomOccurrenceRefs, which reindexes
  # every sbom_occurrence_ref and skips orphans. Skipping stops a halted run from blocking the queue.
  skip_if -> { true }

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
end

BackfillSbomOccurrenceRefsIndex.prepend ::Search::Elastic::MigrationObsolete
