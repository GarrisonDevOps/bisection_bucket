# frozen_string_literal: true

class BackfillWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  batch_size 50_000
  batched!
  throttle_delay 1.minute
  retry_on_failure
  space_requirements!

  DOCUMENT_TYPE = WorkItem

  def respect_limited_indexing?
    true
  end

  def space_required_bytes
    issues_index_size_in_bytes = helper.index_size_bytes(index_name: Issue.index_name)
    epics_index_size_in_bytes = helper.index_size_bytes(index_name: Epic.index_name)
    issues_index_size_in_bytes + epics_index_size_in_bytes
  end

  def item_to_preload
    :namespace
  end
end

BackfillWorkItems.prepend ::Search::Elastic::MigrationObsolete
