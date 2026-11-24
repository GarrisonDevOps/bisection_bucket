# frozen_string_literal: true

class AddMobilePushWorkingHoursToUserPreferences < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :user_preferences, :mobile_push_working_hours, :jsonb, default: {}, null: false, if_not_exists: true
  end
end
