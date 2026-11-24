# frozen_string_literal: true

class AddDraftNotesPerMergeRequestToPlanLimits < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :plan_limits, :draft_notes_per_merge_request, :integer, default: 200, null: false
  end
end
