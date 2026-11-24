# frozen_string_literal: true

class BackfillWorkItemsIncorrectData < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 10_000
  throttle_delay 30.seconds

  DOCUMENT_TYPE = WorkItem
  NEW_SCHEMA_VERSION = 25_27
end

BackfillWorkItemsIncorrectData.prepend ::Search::Elastic::MigrationObsolete
