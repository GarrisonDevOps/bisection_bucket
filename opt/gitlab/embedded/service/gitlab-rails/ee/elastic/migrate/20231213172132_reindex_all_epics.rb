# frozen_string_literal: true

class ReindexAllEpics < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  batch_size 10_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

  DOCUMENT_TYPE = Epic

  def respect_limited_indexing?
    true
  end

  def item_to_preload
    :group
  end
end

ReindexAllEpics.prepend ::Search::Elastic::MigrationObsolete
