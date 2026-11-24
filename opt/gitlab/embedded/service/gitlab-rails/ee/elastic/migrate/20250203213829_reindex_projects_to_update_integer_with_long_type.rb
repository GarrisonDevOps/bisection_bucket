# frozen_string_literal: true

class ReindexProjectsToUpdateIntegerWithLongType < Elastic::Migration
  include Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Project
  NEW_SCHEMA_VERSION = 25_06
end

ReindexProjectsToUpdateIntegerWithLongType.prepend ::Search::Elastic::MigrationObsolete
