# frozen_string_literal: true

class AddIndexOnDescriptionVersionIdToWorkItemDecisions < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  INDEX_NAME = 'index_work_item_decisions_on_description_version_id'

  def up
    add_concurrent_index :work_item_decisions, :description_version_id, name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name :work_item_decisions, INDEX_NAME
  end
end
