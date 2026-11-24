# frozen_string_literal: true

class BackfillProjectAccessOnSnippets < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 10_000
  throttle_delay 1.minute
  retry_on_failure

  DOCUMENT_TYPE = Snippet
  NEW_SCHEMA_VERSION = 26_02
end
