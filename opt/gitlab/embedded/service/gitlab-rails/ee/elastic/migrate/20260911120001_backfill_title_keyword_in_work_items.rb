# frozen_string_literal: true

class BackfillTitleKeywordInWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 10_000
  throttle_delay 1.minute
  # Without this, MigrationWorker#execute_migration only re-raises, so a persistently failing run
  # never reaches migration.fail and stays current_migration, parking every later migration
  # behind it.
  retry_on_failure

  DOCUMENT_TYPE = WorkItem
  NEW_SCHEMA_VERSION = 26_01
end
