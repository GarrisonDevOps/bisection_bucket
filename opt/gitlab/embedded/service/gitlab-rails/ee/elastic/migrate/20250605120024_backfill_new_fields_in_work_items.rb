# frozen_string_literal: true

class BackfillNewFieldsInWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 10_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = WorkItem
  NEW_SCHEMA_VERSION = 25_23
end

BackfillNewFieldsInWorkItems.prepend ::Search::Elastic::MigrationObsolete
