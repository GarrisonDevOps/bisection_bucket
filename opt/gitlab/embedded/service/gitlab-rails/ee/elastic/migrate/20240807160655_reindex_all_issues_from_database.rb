# frozen_string_literal: true

class ReindexAllIssuesFromDatabase < Elastic::Migration
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

  # rubocop:disable CodeReuse/ActiveRecord -- we need to select only unprocessed ids
  def documents_after_current_id
    ids = ::WorkItems::TypesFramework::Provider.new.find_by_base_type(:epic).id
    document_type.where.not(work_item_type_id: ids).where('issues.id > ?', current_id).order(:id)
  end
  # rubocop:enable CodeReuse/ActiveRecord
end

ReindexAllIssuesFromDatabase.prepend ::Search::Elastic::MigrationObsolete
