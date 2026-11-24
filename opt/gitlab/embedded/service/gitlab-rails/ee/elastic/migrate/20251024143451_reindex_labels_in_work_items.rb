# frozen_string_literal: true

class ReindexLabelsInWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 10_000
  throttle_delay 15.seconds

  DOCUMENT_TYPE = WorkItem
  NEW_SCHEMA_VERSION = 25_44
end

ReindexLabelsInWorkItems.prepend ::Search::Elastic::MigrationObsolete
