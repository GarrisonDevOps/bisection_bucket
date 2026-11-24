# frozen_string_literal: true

class ReindexUsersToUpdateIntegerWithLongType < Elastic::Migration
  include Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = User
  NEW_SCHEMA_VERSION = 25_06
end

ReindexUsersToUpdateIntegerWithLongType.prepend ::Search::Elastic::MigrationObsolete
