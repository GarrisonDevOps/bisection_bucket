# frozen_string_literal: true

class BackfillGroupsToElasticsearch < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  batch_size 50_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

  DOCUMENT_TYPE = Group

  def respect_limited_indexing?
    true
  end

  def item_to_preload
    :parent
  end
end
