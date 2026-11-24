# frozen_string_literal: true

class ReindexAllNotesFromDatabase < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  # INC-14518 only affected GitLab.com, so other instances have nothing to repair.
  skip_if -> { !saas_with_es? }

  batched!
  batch_size 50_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Note

  def respect_limited_indexing?
    true
  end

  def item_to_preload
    [{ project: { namespace: :parent } }, :noteable]
  end

  # rubocop:disable CodeReuse/ActiveRecord -- we need to select only unprocessed ids
  def documents_after_current_id
    document_type.user.where('notes.id > ?', current_id).order(:id)
  end
  # rubocop:enable CodeReuse/ActiveRecord
end
