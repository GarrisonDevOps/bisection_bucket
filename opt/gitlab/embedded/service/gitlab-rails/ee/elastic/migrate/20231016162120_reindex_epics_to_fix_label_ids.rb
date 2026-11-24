# frozen_string_literal: true

class ReindexEpicsToFixLabelIds < Elastic::Migration
  include Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Epic
  NEW_SCHEMA_VERSION = 2310
end

ReindexEpicsToFixLabelIds.prepend ::Search::Elastic::MigrationObsolete
