# frozen_string_literal: true

class ReindexAllIssues < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  batch_size 50_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

  DOCUMENT_TYPE = Issue

  def respect_limited_indexing?
    true
  end

  def item_to_preload
    :project
  end
end

ReindexAllIssues.prepend ::Search::Elastic::MigrationObsolete
