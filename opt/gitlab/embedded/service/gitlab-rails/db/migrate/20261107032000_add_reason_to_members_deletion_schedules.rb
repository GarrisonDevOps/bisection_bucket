# frozen_string_literal: true

class AddReasonToMembersDeletionSchedules < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  # Reversibility tested on the development database: migrating this version down drops the column,
  # and migrating it up again adds it back with the same type, default and NOT NULL constraint.
  def change
    add_column :members_deletion_schedules, :reason, :smallint, default: 0, null: false
  end
end
