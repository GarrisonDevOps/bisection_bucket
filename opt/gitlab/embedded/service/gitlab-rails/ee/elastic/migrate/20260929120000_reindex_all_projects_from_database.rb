# frozen_string_literal: true

class ReindexAllProjectsFromDatabase < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  # INC-14518 only affected GitLab.com, so other instances have nothing to repair.
  skip_if -> { !saas_with_es? }

  batched!
  batch_size 50_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Project

  def respect_limited_indexing?
    false
  end

  def item_to_preload
    { namespace: :parent }
  end
end
