# frozen_string_literal: true

class ReindexMilestones < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  # ReindexAllMilestonesFromDatabase already reindexes every milestone on GitLab.com.
  skip_if -> { saas_with_es? }

  batch_size 50_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

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
