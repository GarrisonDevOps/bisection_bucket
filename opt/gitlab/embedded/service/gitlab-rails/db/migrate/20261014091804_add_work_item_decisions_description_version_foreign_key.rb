# frozen_string_literal: true

class AddWorkItemDecisionsDescriptionVersionForeignKey < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  disable_ddl_transaction!

  def up
    add_concurrent_foreign_key :work_item_decisions, :description_versions,
      column: :description_version_id, on_delete: :nullify
  end

  def down
    with_lock_retries do
      remove_foreign_key_if_exists :work_item_decisions, :description_versions,
        column: :description_version_id
    end
  end
end
