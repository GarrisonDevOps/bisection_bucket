# frozen_string_literal: true

class RemoveUseWorkItemsViewFromUserPreferences < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  def up
    remove_column :user_preferences, :use_work_items_view
  end

  def down
    add_column :user_preferences, :use_work_items_view, :boolean, default: false, null: false
  end
end
