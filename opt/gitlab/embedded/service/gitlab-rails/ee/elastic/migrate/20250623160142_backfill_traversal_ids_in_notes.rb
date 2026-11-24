# frozen_string_literal: true

class BackfillTraversalIdsInNotes < Elastic::Migration
  include Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 10_000
  throttle_delay 30.seconds

  DOCUMENT_TYPE = Note
  NEW_SCHEMA_VERSION = 25_24
  QUEUE_THRESHOLD = 30_000
end

BackfillTraversalIdsInNotes.prepend ::Search::Elastic::MigrationObsolete
