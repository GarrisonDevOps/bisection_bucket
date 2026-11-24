# frozen_string_literal: true

class ReindexAllMilestonesFromDatabase < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  # INC-14518 only affected GitLab.com, so other instances have nothing to repair.
  skip_if -> { !saas_with_es? }

  batched!
  batch_size 50_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Milestone

  def respect_limited_indexing?
    true
  end

  def item_to_preload
    {
      project: { namespace: :parent },
      group: %i[namespace_settings namespace_settings_with_ancestors_inherited_settings]
    }
  end
end
