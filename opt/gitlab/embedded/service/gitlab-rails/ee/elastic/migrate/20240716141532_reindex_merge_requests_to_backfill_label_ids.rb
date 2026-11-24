# frozen_string_literal: true

class ReindexMergeRequestsToBackfillLabelIds < Elastic::Migration
  include Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = MergeRequest
  NEW_SCHEMA_VERSION = 24_08
  UPDATE_BATCH_SIZE = 100
end

ReindexMergeRequestsToBackfillLabelIds.prepend ::Search::Elastic::MigrationObsolete
