# frozen_string_literal: true

class AddDescriptionVersionIdToWorkItemDecisions < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :work_item_decisions, :description_version_id, :bigint
  end
end
