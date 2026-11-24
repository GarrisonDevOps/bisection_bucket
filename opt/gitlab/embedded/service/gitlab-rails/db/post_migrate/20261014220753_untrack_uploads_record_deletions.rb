# frozen_string_literal: true

class UntrackUploadsRecordDeletions < Gitlab::Database::Migration[2.4]
  include Gitlab::Database::MigrationHelpers::LooseForeignKeyHelpers

  milestone '19.6'

  def up
    return unless has_loose_foreign_key?(:uploads)

    untrack_record_deletions(:uploads)
  end

  def down
    return if has_loose_foreign_key?(:uploads)

    track_record_deletions_override_table_name(:uploads)
  end
end
